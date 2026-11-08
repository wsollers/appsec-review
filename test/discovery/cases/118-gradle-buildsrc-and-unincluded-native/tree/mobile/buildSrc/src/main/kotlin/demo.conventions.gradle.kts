tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:all")
}
