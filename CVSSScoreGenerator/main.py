from CVSSScoreGenerator.CVSSStringParser import CVSSStringParser
from CVSSScoreGenerator.CVSSScorePlotter import CVSSScorePlotter


if __name__ == "__main__":
    #string_arg = sys.argv[1]
    #file_name = sys.argv[2]
    parser = CVSSStringParser("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N/E:P/RL:W/RC:C/CR:H/IR:L/AR:L/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:H")
    parser.build_cvss_score()
    parser.score.calculate_all_scores()
    plotter = CVSSScorePlotter(parser.score)
    plotter.build_score_diagrams_and_safe_in_file("test.pdf")
