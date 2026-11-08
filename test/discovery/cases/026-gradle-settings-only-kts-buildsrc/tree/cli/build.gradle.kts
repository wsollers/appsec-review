plugins {
    id("tools-conventions")
    application
}

dependencies {
    implementation(project(":lib"))
}

application {
    mainClass.set("tools.cli.MainKt")
}
