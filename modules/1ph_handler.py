def extract_lph_string(file_content):
    """
    Searches for the LPH! hex string inside a Lua script.
    Returns the hex string or None.
    """
    import re
    match = re.search(r'LPH!([0-9A-Fa-f]+)', file_content)
    return match.group(1) if match else None


def unpack_lph_data(lph_string):
    """
    Decodes LPH string to raw bytes
    """
    if not lph_string.startswith("LPH!"):
        lph_string = "LPH!" + lph_string
    data = lph_string[4:]
    unpacked = []
    i = 0
    while i < len(data):
        if data[i].isdigit():
            count = int(data[i])
            value = data[i + 1]
            unpacked.extend([value] * count)
            i += 2
        else:
            byte = int(data[i:i+2], 16)
            unpacked.append(byte)
            i += 2
    return unpacked
