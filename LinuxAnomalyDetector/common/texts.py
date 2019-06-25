import os
import constants


def load_text(file_name):
    with open(file_name) as fhandle:
        text = fhandle.read()

    return constants.replace_constants(text)


TEXT__PID_COMMAND = load_text(os.path.join(
    constants.PROJECT_ROOT_PATH,
    "common/texts/text__pid_command.c"))
