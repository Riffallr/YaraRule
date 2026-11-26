rule onCreateFile {
    meta:
        author = "Riffall"
        description = "Find CreateFile function"
        date = "2026-11-26"
        reference = "https://github.com/Riffallr/-WIPER-_MemoryBootRecord_Eater"
    strings:
        $createFile =  "CreateFileW"
    condition:
        $createFile
}

rule onWriteFile {
    meta:
        author = "Riffall"
        description = "Find WriteFile function"
        date = "2026-11-26"
        reference = "https://github.com/Riffallr/-WIPER-_MemoryBootRecord_Eater"
    strings:
        $writeFile = "WriteFile"
    condition:
        $writeFile
}

rule onURL {
    meta:
        author = "Riffall"
        description = "Find any URL"
        date = "2026-11-26"
        reference = "https://github.com/Riffallr/-WIPER-_MemoryBootRecord_Eater"
    strings:
        $url = /https?:\/\/[a-zA-Z0-9\.\-]+/ wide
	$url1 = /https?:\/\/[a-zA-Z0-9\.\-]+/ 
    condition:
       	any of them
}