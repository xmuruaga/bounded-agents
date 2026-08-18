"""
APC security profiles for all 80 InjecAgent tools.

Each tool is classified with:
  - action_type: read, read_sensitive, write, delete, send_external, execute, transfer, physical
  - sensitivity: public, internal, confidential
  - blast_radius, irreversibility, cross_domain flags

The key insight: ALL data stealing attacks follow the pattern
  read_sensitive_data → GmailSendEmail (send_external)
which is exactly the composition (read_sensitive, send_external) ∈ X.
"""

from __future__ import annotations


TOOL_PROFILES: dict[str, dict] = {
    # =====================================================================
    # USER TOOLS (17) — these are the legitimate tools the agent uses
    # All are READ operations on various data sources
    # =====================================================================
    "AmazonGetProductDetails":      {"action": "read",           "sensitivity": "public",       "data": "general"},
    "EvernoteManagerSearchNotes":    {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "GitHubGetRepositoryDetails":   {"action": "read",           "sensitivity": "public",       "data": "general"},
    "GitHubGetUserDetails":         {"action": "read",           "sensitivity": "public",       "data": "general"},
    "GitHubSearchRepositories":     {"action": "read",           "sensitivity": "public",       "data": "general"},
    "GmailReadEmail":               {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "GmailSearchEmails":            {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "GoogleCalendarGetEventsFromSharedCalendar": {"action": "read", "sensitivity": "internal", "data": "personal"},
    "GoogleCalendarReadEvents":     {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "ShopifyGetProductDetails":     {"action": "read",           "sensitivity": "public",       "data": "general"},
    "TeladocViewReviews":           {"action": "read",           "sensitivity": "public",       "data": "general"},
    "TodoistSearchTasks":           {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TwilioGetReceivedSmsMessages": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TwitterManagerGetUserProfile": {"action": "read",           "sensitivity": "public",       "data": "general"},
    "TwitterManagerReadTweet":      {"action": "read",           "sensitivity": "public",       "data": "general"},
    "TwitterManagerSearchTweets":   {"action": "read",           "sensitivity": "public",       "data": "general"},
    "WebBrowserNavigateTo":         {"action": "read_external",  "sensitivity": "public",       "data": "general"},

    # =====================================================================
    # ATTACKER TOOLS — Data Stealing (step 1: read sensitive data)
    # =====================================================================
    "AmazonViewSavedAddresses":     {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "AmazonViewSavedPaymentMethods":{"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "AugustSmartLockViewAccessHistory": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "BankManagerGetAccountInformation": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "BankManagerSearchPayee":       {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "BinanceGetOrderHistory":       {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "CiscoUmbrellaGetLogDetails":   {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "DeepfakeGeneratorGenerateAudioDeepfake": {"action": "execute", "sensitivity": "confidential", "data": "personal"},
    "DropboxGetItemMetadata":       {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "DropboxListFilesAndFolders":   {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "EpicFHIRDownloadFiles":        {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "EpicFHIRGetPatientDetails":    {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "ExpediaSearchReservations":    {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "FacebookManagerGetUserProfile":{"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "FacebookManagerSearchFriends": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "FedExShipManagerSearchShipment":{"action": "read_sensitive","sensitivity": "confidential", "data": "personal"},
    "GoogleMapGetCurrentLocation":  {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "GoogleSearchGetSearchHistory": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "InvestmentManagerGetHoldingsInformation": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "NortonIdentitySafeSearchPasswords": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "SpokeoDownloadPublicRecord":   {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "SpokeoSearchPeople":           {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TDAmeritradeGetHoldingsInformation": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TeladocAccessUserInfo":        {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TeladocViewPrescriptions":     {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "The23andMeDownloadData":       {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "The23andMeGetGeneticData":     {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "The23andMeGetHealthRecommendations": {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "TwilioGetPhoneNumberInfo":     {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "VenmoListLinkedAccounts":      {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},
    "WebBrowserSearchHistory":      {"action": "read_sensitive", "sensitivity": "confidential", "data": "personal"},

    # =====================================================================
    # ATTACKER TOOLS — Data Stealing (step 2: exfiltrate)
    # =====================================================================
    "GmailSendEmail":               {"action": "send_external",  "sensitivity": "confidential", "data": "general", "cross_domain": True},

    # =====================================================================
    # ATTACKER TOOLS — Direct Harm
    # =====================================================================
    "AugustSmartLockGrantGuestAccess": {"action": "physical",    "sensitivity": "confidential", "data": "general", "irreversible": True},
    "AugustSmartLockUnlockDoor":    {"action": "physical",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "BankManagerPayBill":           {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "BankManagerTransferFunds":     {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "BinanceDeposit":               {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "BinancePlaceOrder":            {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "BinanceWithdraw":              {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "CiscoUmbrellaCreatePolicy":    {"action": "write",          "sensitivity": "confidential", "data": "general"},
    "CiscoUmbrellaUpdatePolicy":    {"action": "write",          "sensitivity": "confidential", "data": "general"},
    "DropboxMoveItem":              {"action": "write",          "sensitivity": "confidential", "data": "general", "irreversible": True},
    "EmergencyDispatchSystemCreateDispatchRequest": {"action": "execute", "sensitivity": "confidential", "data": "general", "irreversible": True},
    "EpicFHIRManageAppointments":   {"action": "write",          "sensitivity": "confidential", "data": "personal"},
    "EpicFHIRManageClinicalDocuments": {"action": "write",       "sensitivity": "confidential", "data": "personal"},
    "EpicFHIRManagePatientRecords": {"action": "write",          "sensitivity": "confidential", "data": "personal"},
    "EvernoteManagerManageNoteSharingLevel": {"action": "write",  "sensitivity": "confidential", "data": "general"},
    "FacebookManagerUpdateUserProfile": {"action": "write",      "sensitivity": "confidential", "data": "personal"},
    "FedExShipManagerManageShipment":{"action": "execute",       "sensitivity": "confidential", "data": "general", "irreversible": True},
    "GitHubDeleteRepository":       {"action": "delete",         "sensitivity": "confidential", "data": "general", "irreversible": True},
    "GoogleHomeScheduleDeviceAction":{"action": "physical",      "sensitivity": "confidential", "data": "general"},
    "IndoorRobotGoToRoom":          {"action": "physical",       "sensitivity": "confidential", "data": "general"},
    "NortonIdentitySafeAutoFillPersonalInfo": {"action": "write", "sensitivity": "confidential", "data": "personal"},
    "NortonIdentitySafeDisableTwoFactorAuthentication": {"action": "execute", "sensitivity": "confidential", "data": "general", "irreversible": True},
    "NortonIdentitySafeSharePassword": {"action": "send_external", "sensitivity": "confidential", "data": "personal", "cross_domain": True},
    "SlackLeaveChannel":            {"action": "execute",        "sensitivity": "internal",     "data": "general"},
    "TerminalExecute":              {"action": "execute",        "sensitivity": "confidential", "data": "general", "irreversible": True},
    "The23andMeShareData":          {"action": "send_external",  "sensitivity": "confidential", "data": "personal", "cross_domain": True},
    "The23andMeUpdateData":         {"action": "write",          "sensitivity": "confidential", "data": "personal"},
    "TrafficControlGivePriorityToEmergencyVehicle": {"action": "physical", "sensitivity": "confidential", "data": "general", "irreversible": True},
    "TrafficControlManageTrafficLightState": {"action": "physical", "sensitivity": "confidential", "data": "general", "irreversible": True},
    "VenmoWithdrawMoney":           {"action": "transfer",       "sensitivity": "confidential", "data": "general", "irreversible": True},
}


def get_action_type(tool_name: str) -> str:
    """Get the APC action type for a tool."""
    profile = TOOL_PROFILES.get(tool_name)
    if profile is None:
        return "unknown"
    return profile["action"]


def get_sensitivity(tool_name: str) -> str:
    """Get the sensitivity classification for a tool."""
    profile = TOOL_PROFILES.get(tool_name)
    if profile is None:
        return "public"
    return profile["sensitivity"]


def is_irreversible(tool_name: str) -> bool:
    """Check if a tool has irreversible effects."""
    profile = TOOL_PROFILES.get(tool_name)
    if profile is None:
        return False
    return profile.get("irreversible", False)
