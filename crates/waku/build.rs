fn main() {
    let proto_dir = "proto";
    let protos = [
        "proto/message.proto",
        "proto/light_push.proto",
        "proto/peer_exchange.proto",
        "proto/metadata.proto",
        "proto/filter.proto",
        "proto/store.proto",
    ];

    let descriptors = protox::compile(protos, [proto_dir]).expect("failed to compile protos");
    prost_build::compile_fds(descriptors).expect("failed to generate protobuf bindings");

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
