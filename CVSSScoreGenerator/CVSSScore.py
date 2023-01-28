import math


class CVSSScore:
    """
    Use a CVSS score to store and calculate the related CVSS data, describing the severity of a vulnerability based on a
    scale from 0 to 10.
    """

    def __init__(self):
        # Initialize all base parameters with 0, so all calculations are possible and might just return 0, if a score is
        # not properly initialized.
        # It could also be the case that only the base parameters are assigned, while some parameters of a CVSS score
        # are optional.
        self.attack_vector = 0
        self.attack_complexity = 0
        self.privileges_required = 0
        self.user_interaction = 0
        # Boolean value, just used for a check during the calculations.
        self.scope_changed = False
        self.confidentiality_impact = 0
        self.integrity_impact = 0
        self.availability_impact = 0
        self.exploit_code_maturity = 0
        self.remediation_level = 0
        self.report_confidence = 0
        self.modified_attack_vector = 0
        self.modified_attack_complexity = 0
        self.modified_privileges_required = 0
        self.modified_user_interaction = 0
        # Boolean value, just used for a check during the calculations.
        self.modified_scope_changed = False
        self.modified_confidentiality_impact = 0
        self.modified_integrity_impact = 0
        self.modified_availability_impact = 0
        self.confidentiality_requirement = 0
        self.integrity_requirement = 0
        self.availability_requirement = 0
        # Initialize the scores, which will be calculated, with 0 to ensure that they are at least present, even if they
        # might not be evaluated.
        self.isc_base = 0
        self.isc = 0
        self.exploitability = 0
        self.base_score = 0
        self.temporal_score = 0
        self.miss = 0
        self.modified_impact = 0
        self.modified_exploitability = 0
        self.environmental_score = 0

    @staticmethod
    def round_cvss_like(number):
        """
        The CVSS v3.1 defines a pseudocode implementation of the roundup function, which can be found in the
        specification document.
        It is implemented like described here.
        :param number: The given number to roundup like described in the CVSS specification.
        :return: The rounded number.
        """

        if not number:
            return 0

        int_input = int(number * 100000)

        if int_input % 10000 == 0:
            return int_input / 100000.0

        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    def calculate_isc_base(self):
        """
        Calculate the isc base score as impact sub score, defined as:
        1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]
        :return: The value is assigned to the related attribute.
        """

        self.isc_base = 1 - ((1 - self.confidentiality_impact) * (1 - self.integrity_impact) *
                             (1 - self.availability_impact))

    def calculate_isc(self):
        """
        Calculate the impact, defined as:
        If Scope is Unchanged	6.42 × ISS
        If Scope is Changed	7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
        :return: The value is assigned to the related attribute.
        """

        if self.scope_changed:
            self.isc = self.round_cvss_like(7.52 * (self.isc_base - 0.029) - 3.25 * pow((self.isc_base - 0.02), 15))

        else:
            self.isc = self.round_cvss_like(6.42 * self.isc_base)

    def calculate_exploitability(self):
        """
        Calculate the exploitability, defined as:
        8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
        :return: The value is assigned to the related attribute.
        """

        self.exploitability = self.round_cvss_like(8.22 * self.attack_vector * self.attack_complexity *
                                                   self.privileges_required * self.user_interaction)

    def calculate_base_score(self):
        """
        Calculate the base score, defined as:
        If Impact \<= 0	0, else
        If Scope is Unchanged	Roundup (Minimum [(Impact + Exploitability), 10])
        If Scope is Changed	Roundup (Minimum [1.08 × (Impact + Exploitability), 10])
        :return: The value is assigned to the related attribute.
        """

        if self.isc <= 0:
            self.base_score = 0

        elif self.scope_changed:
            self.base_score = self.round_cvss_like(min((1.08 * (self.isc + self.exploitability)), 10))

        else:
            self.base_score = self.round_cvss_like(min((self.isc + self.exploitability), 10))

    def calculate_temporal_score(self):
        """
        Calculate the temporal score, defined as:
        Roundup (BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
        :return: The value is assigned to the related attribute.
        """

        self.temporal_score = self.round_cvss_like(self.base_score * self.exploit_code_maturity *
                                                   self.remediation_level * self.report_confidence)

    def calculate_miss(self):
        """
        Calculate the modified impact sub score, defined as:
        Minimum ( 1 - [ (1 - ConfidentialityRequirement × ModifiedConfidentiality) × (1 - IntegrityRequirement ×
        ModifiedIntegrity) × (1 - AvailabilityRequirement × ModifiedAvailability) ], 0.915)
        :return: The value is assigned to the related attribute.
        """

        # Calculate the modified impact sub scores for CIA separately for better readability.
        confidentiality = 1 - self.modified_confidentiality_impact * self.confidentiality_requirement
        integrity = 1 - self.modified_integrity_impact * self.integrity_requirement
        availability = 1 - self.modified_availability_impact * self.availability_requirement
        self.miss = min((1 - confidentiality * integrity * availability), 0.915)

    def calculate_modified_impact(self):
        """
        Calculate the modified impact, defined as:
        If ModifiedScope is Unchanged	6.42 × MISS
        If ModifiedScope is Changed	7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
        :return: The value is assigned to the related attribute.
        """

        if self.modified_scope_changed:
            self.modified_impact = self.round_cvss_like(
                7.52 * (self.miss - 0.029) - 3.25 * pow((self.miss * 0.9731 - 0.02), 13))

        else:
            self.modified_impact = self.round_cvss_like(6.42 * self.miss)

    def calculate_modified_exploitability(self):
        """
        Calculate the modified exploitability, defined as:
        8.22 × ModifiedAttackVector × ModifiedAttackComplexity × ModifiedPrivilegesRequired × ModifiedUserInteraction
        :return: The value is assigned to the related attribute.
        """

        self.modified_exploitability = self.round_cvss_like(8.22 * self.modified_attack_vector *
                                                            self.modified_attack_complexity *
                                                            self.modified_privileges_required *
                                                            self.modified_user_interaction)

    def calculate_environmental_score(self):
        """
        Calculate the environmental score, defined as:
        If ModifiedImpact \<= 0	0, else
        If ModifiedScope is Unchanged	Roundup ( Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10) ]
        × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
        If ModifiedScope is Changed 	Roundup ( Roundup [Minimum (1.08 × [ModifiedImpact + ModifiedExploitability],
        10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
        :return: The value is assigned to the related attribute.
        """

        if self.modified_impact <= 0:
            self.environmental_score = 0

        elif self.modified_scope_changed:
            self.environmental_score = self.round_cvss_like(
                self.round_cvss_like(min(1.08 * (self.modified_impact + self.modified_exploitability), 10)
                                     * self.exploit_code_maturity * self.remediation_level * self.report_confidence))

        else:
            self.environmental_score = self.round_cvss_like(
                self.round_cvss_like(min((self.modified_impact + self.modified_exploitability), 10)
                                     * self.exploit_code_maturity * self.remediation_level * self.report_confidence))

    def calculate_all_scores(self):
        """
        Call all functions for calculating the different types of scores, based on the initial values of the CVSS score.
        :return: The values are assigned inside the called functions.
        """

        self.calculate_isc_base()
        self.calculate_isc()
        self.calculate_exploitability()
        self.calculate_base_score()
        self.calculate_temporal_score()
        self.calculate_miss()
        self.calculate_modified_impact()
        self.calculate_exploitability()
        self.calculate_environmental_score()

    def get_maximum_score(self):
        """
        Use all calculated scores to find the maximum score, which is used as overall score.
        :return: The maximum score of the different scores of a CVSS score.
        """

        # Find the maximum of the base score, impact, exploitability, temporal score, environmental score and modified
        # impact as the central scores calculated by the CVSS score specification.
        maximum_score = max(self.base_score, self.isc, self.exploitability, self.temporal_score,
                            self.environmental_score, self.modified_impact)

        return maximum_score
