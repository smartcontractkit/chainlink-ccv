fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/ccv/chainaccess/v1/source_reader.proto");
    tonic_build::configure().compile_protos(
        &["../../proto/ccv/chainaccess/v1/source_reader.proto"],
        &["../../proto"],
    )?;
    Ok(())
}
