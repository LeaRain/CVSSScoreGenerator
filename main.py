import sys

from CVSSScorePlotter import CVSSScorePlotter
from CVSSStringParser import CVSSStringParser

if __name__ == "__main__":
    # Read the CVSS string and the file name in a very basic style from the command line.
    string_arg = sys.argv[1]
    file_name = sys.argv[2]
    # Parse the string and build the score: If the string is malformed, the program will break here.
    parser = CVSSStringParser(string_arg)
    parser.build_cvss_score()
    # Calculate all relevant scores.
    parser.score.calculate_all_scores()
    # Plot the scores and save them in a diagram.
    plotter = CVSSScorePlotter(parser.score)
    plotter.build_score_diagrams_and_safe_in_file(file_name)
