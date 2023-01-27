import matplotlib.pyplot as plt


class CVSSScorePlotter:
    def __init__(self, cvss_score):
        font = {'family': 'serif',
                'serif': 'helvet',
                'weight': 'bold',
                'size': 14}

        plt.rc('font', **font)
        plt.rc('text', usetex=True)
        plt.rcParams['figure.figsize'] = [10, 6]
        self.cvss_score = cvss_score

    def build_score_diagrams_and_safe_in_file(self, file_name):
        fig, axs = plt.subplots(1, 4)
        base_scores_labels = ["Base", "Impact", "Exploitability"]
        base_scores_values = [self.cvss_score.base_score, self.cvss_score.isc, self.cvss_score.exploitability]
        axs[0].bar(base_scores_labels, base_scores_values, color="forestgreen")
        axs[0].tick_params(axis='x', rotation=30)
        axs[0].set_title("Base Scores")

        temporal_score_labels = ["Temporal"]
        temporal_score_values = [self.cvss_score.temporal_score]
        axs[1].bar(temporal_score_labels, temporal_score_values, color="darkturquoise")
        axs[1].tick_params(axis='x', rotation=30)
        axs[1].set_title("Temporal Score")

        environmental_score_labels = ["Environmental", "Modified Impact"]
        environmental_score_values = [self.cvss_score.environmental_score, self.cvss_score.modified_impact]
        axs[2].bar(environmental_score_labels, environmental_score_values, color="gold")
        axs[2].tick_params(axis='x', rotation=30)
        axs[2].set_title("Environmental Scores")

        overall_score_labels = ["Overall"]
        overall_score_values = [self.cvss_score.get_maximum_score()]
        axs[3].bar(overall_score_labels, overall_score_values, color="steelblue")
        axs[3].tick_params(axis='x', rotation=30)
        axs[3].set_title("Overall Score")

        colors = ["forestgreen", "darkturquoise", "gold", "steelblue"]

        for ax, x, y, color in zip(axs, [base_scores_labels, temporal_score_labels, environmental_score_labels,
                                         overall_score_labels],
                                   [base_scores_values, temporal_score_values, environmental_score_values,
                                    overall_score_values], colors):
            bars = ax.bar(x, y, color=color)
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2, height, f"{height}", ha="center", va="bottom")
                ax.set_ylim(0, 11)

        plt.suptitle("CVSS v3.1 Scoring")
        plt.tight_layout()
        plt.savefig(file_name)


