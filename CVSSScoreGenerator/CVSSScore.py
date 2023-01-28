import math


class CVSSScore:
    def __init__(self):
        self.attack_vector = 0
        self.attack_complexity = 0
        self.privileges_required = 0
        self.user_interaction = 0
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
        self.modified_scope_changed = False
        self.modified_confidentiality_impact = 0
        self.modified_integrity_impact = 0
        self.modified_availability_impact = 0
        self.confidentiality_requirement = 0
        self.integrity_requirement = 0
        self.availability_requirement = 0
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
        """

        if not number:
            return 0

        int_input = int(number * 100000)

        if int_input % 10000 == 0:
            return int_input / 100000.0

        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    def calculate_isc_base(self):
        self.isc_base = 1 - ((1 - self.confidentiality_impact) * (1 - self.integrity_impact) *
                             (1 - self.availability_impact))

    def calculate_isc(self):
        if self.scope_changed:
            self.isc = self.round_cvss_like(7.52 * (self.isc_base - 0.029) - 3.25 * pow((self.isc_base - 0.02), 15))

        else:
            self.isc = self.round_cvss_like(6.42 * self.isc_base)

    def calculate_exploitability(self):
        self.exploitability = self.round_cvss_like(8.22 * self.attack_vector * self.attack_complexity *
                                                   self.privileges_required * self.user_interaction)

    def calculate_base_score(self):
        if self.isc <= 0:
            self.base_score = 0

        elif self.scope_changed:
            self.base_score = self.round_cvss_like(min((1.08 * (self.isc + self.exploitability)), 10))

        else:
            self.base_score = self.round_cvss_like(min((self.isc + self.exploitability), 10))

    def calculate_temporal_score(self):
        self.temporal_score = self.round_cvss_like(self.base_score * self.exploit_code_maturity *
                                                   self.remediation_level * self.report_confidence)

    def calculate_miss(self):
        confidentiality = 1 - self.modified_confidentiality_impact * self.confidentiality_requirement
        integrity = 1 - self.modified_integrity_impact * self.integrity_requirement
        availability = 1 - self.modified_availability_impact * self.availability_requirement
        self.miss = min((1 - confidentiality * integrity * availability), 0.915)

    def calculate_modified_impact(self):
        if self.modified_scope_changed:
            self.modified_impact = self.round_cvss_like(
                7.52 * (self.miss - 0.029) - 3.25 * pow((self.miss * 0.9731 - 0.02), 13))

        else:
            self.modified_impact = self.round_cvss_like(6.42 * self.miss)

    def calculate_modified_exploitability(self):
        self.modified_exploitability = self.round_cvss_like(8.22 * self.modified_attack_vector *
                                                            self.modified_attack_complexity *
                                                            self.modified_privileges_required *
                                                            self.modified_user_interaction)

    def calculate_environmental_score(self):
        print(self.modified_scope_changed)

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
        maximum_score = max(self.base_score, self.isc, self.exploitability, self.temporal_score,
                            self.environmental_score, self.modified_impact)
        return maximum_score
