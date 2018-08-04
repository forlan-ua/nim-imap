import nake, os


proc runTests() =
    createDir("build")

    discard shell(
        nimExe, 
        "c", "--run", "-d:release", "-d:ssl", 
        "--nimcache:nimcache", "--out:build/tests", 
        "-d:debugImap",
        "tests/tests"
    )


task defaultTask, "Run tests":
    runTests()


task "doc", "Generate docs":
    createDir("build")

    discard shell(
        nimExe, "doc", "-d:ssl", "nimap"
    )
    moveFile("nimap.html", "build/nimap.html")