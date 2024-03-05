rule acropalypse_png
{
    meta:
        description = "Detects the PNG files probably affected by acropalypse"
        author = "Octavio Gianatiempo (ogianatiempo@faradaysec.com)"
    strings:
        $a = "IEND"
    condition:
        // PNG magic
        uint32be(0) == 0x89504E47 and
        uint32be(4) == 0x0D0A1A0A and

        // valid IEND chunk at the end of the file
        uint32be(filesize-12) == 0x0 and
        uint32be(filesize-8) == 0x49454E44 and
        uint32be(filesize-4) == 0xAE426082 and

        // At least two valid IEND chunks
        for 2 i in (1..#a) : ( 
            uint32be(@a[i]-4) == 0x0 and
            uint32be(@a[i]+4) == 0xAE426082
        )
}

rule acropalypse_jpeg
{
    meta:
        description = "Detects the jpeg files probably affected by acropalypse"
        author = "Octavio Gianatiempo (ogianatiempo@faradaysec.com)"
    strings:
        $a = {FF D9}
    condition:
        // JPEG SOI and APP0
        uint16be(0) == 0xFFD8 and
        uint16be(2) == 0xFFE0 and
        uint32be(6) == 0x4A464946 and

        // EOI marker at the end of the file
        uint16be(filesize-2) == 0xFFD9 and

        // At least two valid EOI markers
        #a >= 2
}