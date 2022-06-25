def lohash_digest(data:bytes, hex_digest:bool=False) -> bytes:
    x = [
        0xfadc7dd24fd6785468913955, 0x29564e0379975942e1761186, 0xa389344d09b5fc2d73386bd5, 0x1f55dac05d023386dfc92dfd,
        0x707ef48d550f3fd0e5b84eee, 0x4f0ccea29f1c7c016b7eb211, 0xaa46af8c20b9764a47bf4f8d, 0xac39bace0c8eb3f4e52c4476,
        0x531989071f23401470b215b3, 0x4164dbc5cf6c899a5377e885, 0x70fb2b8b39412273ff200883, 0x3526fa0851df9b4a3b06e4d7,
        0x1cc4503b0210736fbfbf99aa, 0x65ad47c772a5dde4f0cf4533, 0xdc6a4bceca1758eb96b9f49d, 0x9be9754e1a7b363ca036c6e7,
        0xc01c0b67803058c650529bb3, 0x9ba5a6e70e48d542f3a959ed, 0x2b121934efda2c7507bcc0b5, 0x3bf1d78900b4106d6e0b8ce8
    ]

    digest = [0] * 32
    data = list(data + b'\x00' * 32)

    for i in range(len(data)):
        data[i] ^= 0x36

        if data[i] > 0x80:
            data[i] ^= 0x40

        for j in range(32):
            data[i] ^= ((data[i] * 2) + x[(j + 3) % 20]) % 0x800

        if data[i] > 0x600:
            data[i] ^= 0xe92d72ffec8a369d424ebdb6

        try:
            data[i] ^= data[i + 1] ^ 0xcba98307404674221694b04a
        except:
            data[i] ^= data[i - 1] ^ 0x999f6b7e4fc31528aa73b7d7

        data[i] ^= x[(i + 41) % 20]
        x[i % 20] ^= sum(data) // len(data) + (i // 3 + 7)

        digest[i % 32] += data[i] + x[i % 20]
        digest[i % 32] += (0xFFFFFFFF * (digest[i % 32] * 32)) // 40
        x[i % 20] ^= digest[i % 32]

    for i in range(len(digest)):
        digest[i] ^= x[i % 20]
        digest[i] ^= (0xFF * (digest[i] >> 4)) // 40

        try:
            digest[i] ^= digest[i + 1] ^ 0x4cab357149c615fd00a39019
        except:
            digest[i] ^= digest[i - 1] ^ 0xe4c9635cfa4b7913ff2e416c
        
        digest[i] ^= x[i % 20] // 2 
        x[i % 20] ^= sum(digest) // len(digest)
        
        for j in range(20):
            digest[i] ^= x[j] ^ 0x2ab73970edfbd844fe9a10e2

            if j % 2 == 0:
                digest[i] ^= 0x10a9cf41008cef19f186709a
                if digest[i] % 2 == 0:
                    digest[i] ^= 0xc9ab3c9714c6108888110f3f

            try:
                digest[i] ^= x[j + 1] ^ 0xaa6f2c0f406d455c63700a2f
            except:
                digest[i] ^= x[j - 1] ^ 0x42882c4275d2bfb7371ad1a6

            digest[i] ^= x[j] ^ 0x688a85912fad5559ca102b3b

            if i % 2 == 0:
                digest[i] ^= 0x91367f35fa11c06434284abb
            else:
                digest[i] ^= 0x68104f43dd43e03e57365e27
            
            digest[i] ^= sum(x) // len(x) + (i + 5 * j + 9)
            digest[i] ^= sum(data) // len(data) + (i + 3 * j + 7)

        digest[i] %= 256

    digest = bytes(digest)

    return digest.hex() if hex_digest else digest
