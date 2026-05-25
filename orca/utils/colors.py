"""Terminal color constants."""

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Short aliases for scanner output
    s = f"{OKGREEN}[+]{ENDC}"      # success
    e = f"{FAIL}[-]{ENDC}"         # error
    w = f"{WARNING}[!]{ENDC}"      # warning
    i = f"{OKCYAN}[*]{ENDC}"       # info
    t = f"{OKBLUE}[~]{ENDC}"       # try/attempt
