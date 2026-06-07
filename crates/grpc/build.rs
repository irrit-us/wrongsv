fn main() {
    prost_build::compile_protos(&["proto/gun.proto"], &["proto/"]).unwrap();
}
