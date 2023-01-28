import re
from CVSSScoreGenerator.CVSSScore import CVSSScore


# Use dictionaries to describe the values given by the specification document for the different parts of the cvss
# string.
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
    """
    Use a parser to read CVSS strings and assign the relevant values to a resulting score.
    """

    def __init__(self, cvss_string):
        # Define a list for the metrics: The metrics are the different categories to describe the severity of a
        # vulnerability.
        self.metrics_list = []
        # Parse the string.
        self.parse_cvss_string_to_metrics_list(cvss_string)
        # Create a CVSS score to use later for the parsed metrics.
        self.score = CVSSScore()

    def parse_cvss_string_to_metrics_list(self, cvss_string):
        """
        Get an input string and try to parse it by also validating it.
        :param cvss_string: A raw input string, for example based on user input.
        :return: Values are assigned to the metrics list.
        """

        # The delimiter between two metrics is a "/", so here we get single metrics to check them one by one.
        metrics_list = cvss_string.split("/")

        for metric in metrics_list:
            # Check for a valid metric pattern.
            # If a metric is not valid, the metric is just skipped without an error message, so the rest of the string
            # is parsed correctly.
            if self.parse_valid_metric_pattern(metric):
                # Append a correctly parsed metric to the metric list.
                self.metrics_list.append(metric)

    @staticmethod
    def parse_valid_metric_pattern(metric):
        """
        Check a given metric for a valid pattern, which starts with one to three upper case letters, separated by a :
        and with one upper case letter in the end.
        The first part describes the type/category and the second one holds a letter for the scoring.
        :param metric: A metric to parse and check.
        :return: If a match is found, True, else None.
        """

        # Check the metric for the correct pattern.
        # Notice the usage of the full match function to ensure the metric contains the exact valid pattern.
        match_result = re.fullmatch(r"^[A-Z]{1,3}:[A-Z]$", metric)

        # Return the result for a(n in)valid metric.
        if match_result:
            return True

    def build_cvss_score(self):
        """
        Use the metric list with (parsed) metrics to populate the CVSS score with the initial values.
        :return: Values are assigned to the attribute score.
        """

        # Find the changed scope values and assign them.
        scope_changed_values = self.get_scope_changed_values()
        # Get the value for "scope changed" and "modified scope changed" as result of the previous function.
        self.score.scope_changed = scope_changed_values[0]
        self.score.modified_scope_changed = scope_changed_values[1]

        # Evaluate every metric in the previous build metric list.
        for metric in self.metrics_list:
            # Split the metric exactly one time at the ":" to get the metric type and the related scoring.
            metric_split = metric.split(":", 1)

            # If the length of the resulting list is not exactly two, meaning there is one metric type and a scoring,
            # raise an error, because in this case, the CVSS string is considered malformed.
            if len(metric_split) != 2:
                raise ValueError

            # Get the type and the value of a metric.
            metric_type, metric_scoring = metric_split[0], metric_split[1]
            # Store the metric with its type and value by calling the related function.
            self.store_metric_with_value(metric_type, metric_scoring)

    def get_scope_changed_values(self):
        """
        Find the values for a (modified) changed scope in the CVSS string by looking for the correct type in the given
        CVSS string.
        :return: The two values for the changed scope as boolean, if they are found and False as default.
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
        """
        Use a metric with its given type and scoring to store it as part of the CVSS score by using the pre-defined
        dictionaries to get the correct numeric values.
        :param metric_type: The type of metric, which is a category to describe the vulnerability further, for example
        the impact on confidentiality, integrity and availability or the related skill level of an attacker to proceed
        with an attack.
        :param metric_scoring: The scoring of metric, described by a letter, related to a numeric value for each type
        of metric.
        :return: Values are assigned by using the class attribute score, representing the CVSS score.
        """

        # Check the given metric type for all available metric types with one if/elif statement.
        # Notice that if a given metric type is not found, for example if a malformed metric is part of the string, it
        # is just ignored, while an incorrect scoring results in an explicit error.
        if metric_type == "AV":
            self.score.attack_vector = attack_vector_values[metric_scoring]

        elif metric_type == "AC":
            self.score.attack_complexity = attack_complexity_values[metric_scoring]

        elif metric_type == "PR":
            # Some metrics have different values, based on a changed (modified) scope.
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

