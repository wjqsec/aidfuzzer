class TextColor:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

# Function to print colorful text with different foreground and background colors
def print_colorful_text(text, foreground_color=''):
    full_text = foreground_color + text + '\033[0m'  # Reset color to default
    print(full_text)