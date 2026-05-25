"""ORCA security checks."""

from orca.checks.recon import ReconCheck
from orca.checks.endpoints import EndpointsCheck
from orca.checks.misconfig import MisconfigCheck
from orca.checks.sensitive_files import SensitiveFilesCheck
from orca.checks.xss import XSSCheck
from orca.checks.idor import IDORCheck
from orca.checks.auth_issues import AuthIssuesCheck
from orca.checks.disclosure import DisclosureCheck
from orca.checks.rpc_surface import RPCSurfaceCheck
from orca.checks.cve import CVECheck
from orca.checks.fuzzer import FuzzerCheck
from orca.checks.reports import ReportsCheck
from orca.checks.lfi import LFICheck
from orca.checks.ssrf import SSRFCheck
from orca.checks.exposure import ExposureCheck
from orca.checks.source_leak import SourceLeakCheck

ALL_CHECKS = [
    ReconCheck,
    EndpointsCheck,
    MisconfigCheck,
    SensitiveFilesCheck,
    XSSCheck,
    IDORCheck,
    AuthIssuesCheck,
    DisclosureCheck,
    RPCSurfaceCheck,
    CVECheck,
    FuzzerCheck,
    ReportsCheck,
    LFICheck,
    SSRFCheck,
    ExposureCheck,
    SourceLeakCheck,
]
