fn main() {
    prost_build::compile_protos(&["proto/addons.proto"], &["proto/"]).unwrap();
}
