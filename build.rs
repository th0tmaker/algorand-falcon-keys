// build.rs

fn main() {
    cc::Build::new()
        .file("vendor/falcon/codec.c")
        .file("vendor/falcon/common.c")
        .file("vendor/falcon/deterministic.c")
        .file("vendor/falcon/falcon.c")
        .file("vendor/falcon/fft.c")
        .file("vendor/falcon/fpr.c")
        .file("vendor/falcon/keygen.c")
        .file("vendor/falcon/rng.c")
        .file("vendor/falcon/shake.c")
        .file("vendor/falcon/sign.c")
        .file("vendor/falcon/vrfy.c")
        .define("FALCON_FPEMU", "1")   // use integer FP emulation
        .define("FALCON_FMA", "0")     // disable fused multiply-add
        .define("FALCON_AVX2", "0")    // disable AVX2 intrinsics
        .compile("falcon_det1024");
}