import matplotlib.pyplot as plt


class CVSSScorePlotter:
    """
    Use a plotter, which uses a CVSS score as input to build a CVSS plot based on the main scores.
    """

    def __init__(self, cvss_score):
        # Define the font and assign it.
        font = {'family': 'serif',
                'serif': 'helvet',
                'weight': 'bold',
                'size': 14}
        plt.rc('font', **font)
        # Use TeX to generate graphs, which will look beautiful in a LaTeX document.
        plt.rc('text', usetex=True)
        # Define the figure size, so it will look beautiful.
        plt.rcParams['figure.figsize'] = [10, 6]
        self.cvss_score = cvss_score

    def build_score_diagrams_and_safe_in_file(self, file_name):
        """
        Use the score itself to build the related diagrams: Four different ones with the base score with the impact
        score and the exploitability, the temporal score and the environmental score with the modified impact.
        Show also the overall score in a separate diagram.
        Save the result into a .pdf file.
        :param file_name: The name of the file to save the resulting plot.
        :return: The result is saved in a file.
        """

        # Create the figure and the axes for the four different bars.
        fig, axs = plt.subplots(1, 4)
        # Build the base score bar.
        base_scores_labels = ["Base", "Impact", "Exploitability"]
        base_scores_values = [self.cvss_score.base_score, self.cvss_score.isc, self.cvss_score.exploitability]
        axs[0].bar(base_scores_labels, base_scores_values, color="forestgreen")
        axs[0].tick_params(axis='x', rotation=30)
        axs[0].set_title("Base Scores")

        # Build the temporal score bar.
        temporal_score_labels = ["Temporal"]
        temporal_score_values = [self.cvss_score.temporal_score]
        axs[1].bar(temporal_score_labels, temporal_score_values, color="darkturquoise")
        axs[1].tick_params(axis='x', rotation=30)
        axs[1].set_title("Temporal Score")

        # Build the environmental score bar.
        environmental_score_labels = ["Environmental", "Modified Impact"]
        environmental_score_values = [self.cvss_score.environmental_score, self.cvss_score.modified_impact]
        axs[2].bar(environmental_score_labels, environmental_score_values, color="gold")
        axs[2].tick_params(axis='x', rotation=30)
        axs[2].set_title("Environmental Scores")

        # Build the overall score bar.
        overall_score_labels = ["Overall"]
        overall_score_values = [self.cvss_score.get_maximum_score()]
        axs[3].bar(overall_score_labels, overall_score_values, color="steelblue")
        axs[3].tick_params(axis='x', rotation=30)
        axs[3].set_title("Overall Score")

        # Define colors for the bars.
        colors = ["forestgreen", "darkturquoise", "gold", "steelblue"]

        # Build all of them in a diagram.
        for ax, x, y, color in zip(axs, [base_scores_labels, temporal_score_labels, environmental_score_labels,
                                         overall_score_labels],
                                   [base_scores_values, temporal_score_values, environmental_score_values,
                                    overall_score_values], colors):
            # Set the color.
            bars = ax.bar(x, y, color=color)
            for bar in bars:
                # Define the text at the correct position: The number of each score is written on top of the related
                # bar in the chart.
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2, height, f"{height}", ha="center", va="bottom")
                # Set the y-axis from 0 to 11, so the range from 0 to 10 of CVSS is always visible.
                ax.set_ylim(0, 11)

        plt.suptitle("CVSS v3.1 Scoring")
        # Beautify it.
        plt.tight_layout()
        # Save the result like described before.
        plt.savefig(file_name)


