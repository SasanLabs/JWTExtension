version = "1"
description = "Detect, Show, Edit, Fuzz JWT requests"

zapAddOn {
    addOnName.set("JWT Extension")
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("org.json:json:20190722")
}
