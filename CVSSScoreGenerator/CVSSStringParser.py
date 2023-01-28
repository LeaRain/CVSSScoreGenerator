import re
from CVSSScoreGenerator.CVSSScore import CVSSScore


attack_vector_values = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.2
}

attack_complexity_values = {
    "L": 0.77,
    "H": 0.44
}

privileges_required_unchanged_values = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27
}

privileges_required_changed_values = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.5
}

user_interaction_values = {
    "N": 0.85,
    "R": 0.62
}

cia_impact_values = {
    "H": 0.56,
    "L": 0.22,
    "N": 0
}

exploit_code_maturity_values = {
    "X": 1,
    "U": 0.91,
    "P": 0.94,
    "F": 0.97,
    "H": 1
}

remediation_level_values = {
    "X": 1,
    "O": 0.95,
    "T": 0.96,
    "W": 0.97,
    "U": 1
}

report_confidence_values = {
    "X": 1,
    "U": 0.92,
    "R": 0.96,
    "C": 1
}

requirement_values = {
    "X": 1,
    "L": 0.5,
    "M": 1,
    "H": 1.5
}


class CVSSStringParser:
    def __init__(self, cvss_string):
        self.metrics_list = []
        self.parse_cvss_string_to_metrics_list(cvss_string)
        self.score = CVSSScore()

    def parse_cvss_string_to_metrics_list(self, cvss_string):
        metrics_list = cvss_string.split("/")

        for metric in metrics_list:
            if self.parse_valid_metric_pattern(metric):
                self.metrics_list.append(metric)

    @staticmethod
    def parse_valid_metric_pattern(metric):
        match_result = re.fullmatch(r"^[A-Z]{1,3}:[A-Z]$", metric)

        if match_result:
            return True

    def build_cvss_score(self):
        # Find the changed scope values and assign them.
        scope_changed_values = self.get_scope_changed_values()
        self.score.scope_changed = scope_changed_values[0]
        self.score.modified_scope_changed = scope_changed_values[1]

        for metric in self.metrics_list:
            metric_split = metric.split(":", 1)

            if len(metric_split) != 2:
                raise ValueError

            metric_type, metric_scoring = metric_split[0], metric_split[1]
            self.store_metric_with_value(metric_type, metric_scoring)

    def get_scope_changed_values(self):
        """
        Find the values for a (modified) changed scope in the CVSS string and return them accordingly.
        """

        # Set default values to False, just in case the values are not found or are unchanged.
        scope_changed, modified_scope_changed = False, False

        # Go fishing for the (modified) scope changed part of the CVSS string with a list comprehension, looking for the
        # correct metric to evaluate.
        scope_changed_value = [item for item in self.metrics_list if item.startswith("S:")]
        modified_scope_changed_value = [item for item in self.metrics_list if item.startswith("MS:")]

        # Assign the changed scope for both metrics, if applicable.
        if scope_changed_value and scope_changed_value[0] == "S:C":
            scope_changed = True

        if modified_scope_changed_value and modified_scope_changed_value[0] == "MS:C":
            modified_scope_changed = True

        return scope_changed, modified_scope_changed

    def store_metric_with_value(self, metric_type, metric_scoring):
        if metric_type == "AV":
            self.score.attack_vector = attack_vector_values[metric_scoring]

        elif metric_type == "AC":
            self.score.attack_complexity = attack_complexity_values[metric_scoring]

        elif metric_type == "PR":
            if self.score.scope_changed:
                self.score.privileges_required = privileges_required_changed_values[metric_scoring]

            else:
                self.score.privileges_required = privileges_required_changed_values[metric_scoring]

        elif metric_type == "UI":
            self.score.user_interaction = user_interaction_values[metric_scoring]

        elif metric_type == "C":
            self.score.confidentiality_impact = cia_impact_values[metric_scoring]

        elif metric_type == "I":
            self.score.integrity_impact = cia_impact_values[metric_scoring]

        elif metric_type == "A":
            self.score.availability_impact = cia_impact_values[metric_scoring]

        elif metric_type == "E":
            self.score.exploit_code_maturity = exploit_code_maturity_values[metric_scoring]

        elif metric_type == "RL":
            self.score.remediation_level = remediation_level_values[metric_scoring]

        elif metric_type == "RC":
            self.score.report_confidence = report_confidence_values[metric_scoring]

        elif metric_type == "MAV":
            self.score.modified_attack_vector = attack_vector_values[metric_scoring]

        elif metric_type == "MAC":
            self.score.modified_attack_complexity = attack_complexity_values[metric_scoring]

        elif metric_type == "MPR":
            if self.score.modified_scope_changed:
                self.score.modified_privileges_required = privileges_required_changed_values[metric_scoring]

            else:
                self.score.modified_privileges_required = privileges_required_unchanged_values[metric_scoring]

        elif metric_type == "MUI":
            self.score.modified_user_interaction = user_interaction_values[metric_scoring]

        elif metric_type == "MC":
            self.score.modified_confidentiality_impact = cia_impact_values[metric_scoring]

        elif metric_type == "MI":
            self.score.modified_integrity_impact = cia_impact_values[metric_scoring]

        elif metric_type == "MA":
            self.score.modified_availability_impact = cia_impact_values[metric_scoring]

        elif metric_type == "CR":
            self.score.confidentiality_requirement = requirement_values[metric_scoring]

        elif metric_type == "IR":
            self.score.integrity_requirement = requirement_values[metric_scoring]

        elif metric_type == "AR":
            self.score.availability_requirement = requirement_values[metric_scoring]

