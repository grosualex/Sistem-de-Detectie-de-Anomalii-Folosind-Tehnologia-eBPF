PROJECT_ROOT_PATH = ""

CONTSTANTS = {
    "MAX_FILENAME": str(64),
    "MAX_PROCESS_COMMAND": str(64)
}


def replace_constants(text):
    global CONTSTANTS

    for constant in CONTSTANTS:
        text = text.replace(constant, CONTSTANTS[constant])

    return text
