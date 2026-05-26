//! Padding scheme parser — mirrors anytls-go `padding` package.
//!
//! Format: `stop=N\n0=min-max,c,min-max\n1=min-max\n...`
//!
//! Each stage (0-7) defines comma-separated rules:
//! - `min-max` — random size in [min, max) bytes
//! - `c` — "check mark": include actual payload if available
//! - `min-max` with same min=max — fixed size

use rand::Rng;

/// Parsed padding scheme with rules for session stages 0–7.
#[derive(Debug, Clone)]
pub struct PaddingScheme {
    /// Packet index after which padding stops
    pub stop: u32,
    /// Raw scheme bytes (for MD5 fingerprinting / re-transmission)
    pub raw: Vec<u8>,
    /// Per-stage generation rules
    pub stages: Vec<Vec<StageRule>>,
}

#[derive(Debug, Clone)]
pub enum StageRule {
    /// Random size in [min, max) bytes
    Range(i64, i64),
    /// Check mark — include payload if available
    CheckMark,
}

impl PaddingScheme {
    /// Parse a padding scheme from raw bytes.
    ///
    /// Returns `None` if the scheme is malformed or missing the `stop` key.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop: Option<u32> = None;
        // Max stages: 0-7
        let mut stage_rules: Vec<Option<Vec<StageRule>>> = vec![None; 8];

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key == "stop" {
                stop = Some(value.trim().parse().ok()?);
            } else if let Ok(stage) = key.parse::<usize>() {
                if stage < 8 {
                    let rules = parse_rules(value.trim())?;
                    stage_rules[stage] = Some(rules);
                }
            }
        }

        let stop = stop?;
        let stages: Vec<Vec<StageRule>> = stage_rules
            .into_iter()
            .map(|r| r.unwrap_or_default())
            .collect();

        Some(PaddingScheme {
            stop,
            raw: raw.to_vec(),
            stages,
        })
    }

    /// Generate payload/padding sizes for a given packet index.
    ///
    /// Returns a list of sizes. Each positive size indicates how many bytes to send
    /// (payload or padding). `CheckMark` positions in the rule list are replaced
    /// with the actual payload at send time (handled by the caller).
    pub fn generate_sizes(&self, pkt: u32) -> Vec<i64> {
        if pkt >= self.stop {
            return Vec::new();
        }
        let stage = (pkt as usize).min(self.stages.len() - 1);
        let rules = &self.stages[stage];
        if rules.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        rules
            .iter()
            .map(|rule| match rule {
                StageRule::CheckMark => -1, // sentinel for check-mark
                StageRule::Range(min, max) => {
                    if min == max {
                        *min
                    } else {
                        rng.gen_range(*min..*max)
                    }
                }
            })
            .collect()
    }
}

fn parse_rules(value: &str) -> Option<Vec<StageRule>> {
    let mut rules = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "c" {
            rules.push(StageRule::CheckMark);
        } else if let Some((min_str, max_str)) = part.split_once('-') {
            let min: i64 = min_str.trim().parse().ok()?;
            let max: i64 = max_str.trim().parse().ok()?;
            let (min, max) = (min.min(max), min.max(max));
            if min <= 0 || max <= 0 {
                continue;
            }
            rules.push(StageRule::Range(min, max));
        }
    }
    if rules.is_empty() {
        return None;
    }
    Some(rules)
}
