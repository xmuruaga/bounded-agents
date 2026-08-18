"""
Maps AgentDojo tool names to APC ActionTypes and security profiles.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSecurityProfile:
    tool_name: str
    action_type: str
    default_sensitivity: str = "public"
    blast_radius: float = 0.0
    irreversible_effects: int = 0
    is_cross_domain: bool = False
    compute_cost: float = 0.0
    irreversibility_score: float = 0.0
    blast_radius_score: float = 0.0
    sensitivity_score: float = 0.0


@dataclass(frozen=True)
class ActionClassifier:
    _profiles: dict[str, ToolSecurityProfile]

    def classify(self, tool_name: str) -> ToolSecurityProfile | None:
        return self._profiles.get(tool_name)

    @property
    def known_tools(self) -> frozenset[str]:
        return frozenset(self._profiles.keys())

    @staticmethod
    def for_workspace() -> ActionClassifier:
        profiles = {
            "get_unread_emails": _p("get_unread_emails", "read", "internal"),
            "get_received_emails": _p("get_received_emails", "read", "internal"),
            "get_sent_emails": _p("get_sent_emails", "read", "internal"),
            "search_emails": _p("search_emails", "read", "internal"),
            "get_email_by_id": _p("get_email_by_id", "read", "confidential", br=0.05),
            "send_email": _p("send_email", "send_external", "confidential", br=0.3, irr=1, cross=True, irr_s=0.9, br_s=0.7, se_s=0.8),
            "reply_to_email": _p("reply_to_email", "send_external", "confidential", br=0.25, irr=1, cross=True, irr_s=0.8, br_s=0.6, se_s=0.7),
            "forward_email": _p("forward_email", "send_external", "confidential", br=0.3, irr=1, cross=True, irr_s=0.9, br_s=0.7, se_s=0.8),
            "delete_email": _p("delete_email", "delete", "internal", br=0.1, irr=1, irr_s=0.7),
            "get_day_calendar_events": _p("get_day_calendar_events", "read", "internal"),
            "search_calendar_events": _p("search_calendar_events", "read", "internal"),
            "create_calendar_event": _p("create_calendar_event", "write", "internal", br=0.05),
            "cancel_calendar_event": _p("cancel_calendar_event", "delete", "internal", br=0.1, irr=1),
            "reschedule_calendar_event": _p("reschedule_calendar_event", "write", "internal"),
            "invite_user_to_event": _p("invite_user_to_event", "send_internal", "internal", br=0.1),
            "add_calendar_event_participants": _p("add_calendar_event_participants", "send_internal", "internal", br=0.1),
            "search_files_by_filename": _p("search_files_by_filename", "read", "internal"),
            "search_files": _p("search_files", "read", "internal"),
            "get_file_by_id": _p("get_file_by_id", "read", "confidential", br=0.05),
            "create_file": _p("create_file", "write", "internal", br=0.05),
            "append_to_file": _p("append_to_file", "write", "internal", br=0.05),
            "delete_file": _p("delete_file", "delete", "internal", br=0.1, irr=1),
            "get_contacts": _p("get_contacts", "read", "internal"),
            "search_contacts_by_name": _p("search_contacts_by_name", "read", "internal"),
            "search_contacts_by_email": _p("search_contacts_by_email", "read", "internal"),
            "get_contact_by_id": _p("get_contact_by_id", "read", "internal"),
            "get_current_day": _p("get_current_day", "read", "public"),
            "get_draft_emails": _p("get_draft_emails", "read", "internal"),
            "list_files": _p("list_files", "read", "internal"),
            "share_file": _p("share_file", "send_internal", "internal", br=0.15, irr=1, irr_s=0.6, br_s=0.4, se_s=0.5),
            "get_webpage": _p("get_webpage", "read_external", "public", cross=True),
            "post_webpage": _p("post_webpage", "send_external", "confidential", br=0.4, irr=1, cross=True, irr_s=0.9, br_s=0.8, se_s=0.9),
        }
        return ActionClassifier(_profiles=profiles)

    @staticmethod
    def for_banking() -> ActionClassifier:
        profiles = {
            "get_balance": _p("get_balance", "read", "confidential", br=0.05),
            "get_most_recent_transactions": _p("get_most_recent_transactions", "read", "confidential", br=0.05),
            "get_scheduled_transactions": _p("get_scheduled_transactions", "read", "confidential", br=0.05),
            "get_iban": _p("get_iban", "read_sensitive", "confidential", br=0.1),
            "get_user_info": _p("get_user_info", "read_sensitive", "confidential", br=0.1),
            "read_file": _p("read_file", "read", "internal"),
            "send_money": _p("send_money", "transfer", "confidential", br=0.5, irr=1, cross=True, irr_s=0.95, br_s=0.8, se_s=0.9),
            "schedule_transaction": _p("schedule_transaction", "transfer", "confidential", br=0.4, irr=1, irr_s=0.9, br_s=0.7, se_s=0.8),
            "update_scheduled_transaction": _p("update_scheduled_transaction", "write", "confidential", br=0.3),
            "update_password": _p("update_password", "write", "confidential", br=0.2, irr=1, irr_s=0.8, br_s=0.5, se_s=0.9),
            "update_user_info": _p("update_user_info", "write", "confidential", br=0.15),
            "get_webpage": _p("get_webpage", "read_external", "public", cross=True),
            "post_webpage": _p("post_webpage", "send_external", "confidential", br=0.4, irr=1, cross=True, irr_s=0.9, br_s=0.8, se_s=0.9),
        }
        return ActionClassifier(_profiles=profiles)

    @staticmethod
    def for_travel() -> ActionClassifier:
        profiles = {
            # Read operations — hotels, flights, restaurants, cars
            "get_all_hotels_in_city": _p("get_all_hotels_in_city", "read", "public"),
            "get_hotels_prices": _p("get_hotels_prices", "read", "public"),
            "get_hotels_address": _p("get_hotels_address", "read", "public"),
            "get_rating_reviews_for_hotels": _p("get_rating_reviews_for_hotels", "read", "public"),
            "get_flight_information": _p("get_flight_information", "read", "public"),
            "get_all_restaurants_in_city": _p("get_all_restaurants_in_city", "read", "public"),
            "get_cuisine_type_for_restaurants": _p("get_cuisine_type_for_restaurants", "read", "public"),
            "get_dietary_restrictions_for_all_restaurants": _p("get_dietary_restrictions_for_all_restaurants", "read", "public"),
            "get_rating_reviews_for_restaurants": _p("get_rating_reviews_for_restaurants", "read", "public"),
            "get_restaurants_address": _p("get_restaurants_address", "read", "public"),
            "get_price_for_restaurants": _p("get_price_for_restaurants", "read", "public"),
            "get_contact_information_for_restaurants": _p("get_contact_information_for_restaurants", "read", "public"),
            "check_restaurant_opening_hours": _p("check_restaurant_opening_hours", "read", "public"),
            "get_all_car_rental_companies_in_city": _p("get_all_car_rental_companies_in_city", "read", "public"),
            "get_car_types_available": _p("get_car_types_available", "read", "public"),
            "get_car_fuel_options": _p("get_car_fuel_options", "read", "public"),
            "get_car_price_per_day": _p("get_car_price_per_day", "read", "public"),
            "get_car_rental_address": _p("get_car_rental_address", "read", "public"),
            "get_rating_reviews_for_car_rental": _p("get_rating_reviews_for_car_rental", "read", "public"),
            "get_user_information": _p("get_user_information", "read_sensitive", "confidential", br=0.1),
            # Calendar (shared with workspace)
            "get_day_calendar_events": _p("get_day_calendar_events", "read", "internal"),
            "search_calendar_events": _p("search_calendar_events", "read", "internal"),
            "create_calendar_event": _p("create_calendar_event", "write", "internal", br=0.05),
            "cancel_calendar_event": _p("cancel_calendar_event", "delete", "internal", br=0.1, irr=1),
            # Reservations — irreversible write operations
            "reserve_hotel": _p("reserve_hotel", "write", "confidential", br=0.2, irr=1, irr_s=0.7, br_s=0.5, se_s=0.6),
            "reserve_restaurant": _p("reserve_restaurant", "write", "internal", br=0.1, irr=1, irr_s=0.5, br_s=0.3, se_s=0.3),
            "reserve_car_rental": _p("reserve_car_rental", "write", "confidential", br=0.2, irr=1, irr_s=0.7, br_s=0.5, se_s=0.6),
            # Email (shared with workspace)
            "send_email": _p("send_email", "send_external", "confidential", br=0.3, irr=1, cross=True, irr_s=0.9, br_s=0.7, se_s=0.8),
        }
        return ActionClassifier(_profiles=profiles)

    @staticmethod
    def for_slack() -> ActionClassifier:
        profiles = {
            # Read operations
            "get_channels": _p("get_channels", "read", "internal"),
            "get_users_in_channel": _p("get_users_in_channel", "read", "internal"),
            "read_channel_messages": _p("read_channel_messages", "read", "internal"),
            "read_inbox": _p("read_inbox", "read", "internal"),
            "get_webpage": _p("get_webpage", "read_external", "public", cross=True),
            # Write operations — messages
            "send_channel_message": _p("send_channel_message", "send_internal", "internal", br=0.1, irr=1, irr_s=0.5, br_s=0.3, se_s=0.3),
            "send_direct_message": _p("send_direct_message", "send_internal", "internal", br=0.1, irr=1, irr_s=0.5, br_s=0.3, se_s=0.3),
            # Admin operations — higher impact
            "invite_user_to_slack": _p("invite_user_to_slack", "write", "internal", br=0.15, irr=1, irr_s=0.6, br_s=0.4, se_s=0.4),
            "remove_user_from_slack": _p("remove_user_from_slack", "delete", "internal", br=0.3, irr=1, irr_s=0.9, br_s=0.7, se_s=0.6),
            "add_user_to_channel": _p("add_user_to_channel", "write", "internal", br=0.1),
            # External
            "post_webpage": _p("post_webpage", "send_external", "confidential", br=0.4, irr=1, cross=True, irr_s=0.9, br_s=0.8, se_s=0.9),
        }
        return ActionClassifier(_profiles=profiles)


def _p(name, action_type, sensitivity="public", br=0.0, irr=0, cross=False,
       cost=0.0, irr_s=0.0, br_s=0.0, se_s=0.0):
    return ToolSecurityProfile(
        tool_name=name, action_type=action_type, default_sensitivity=sensitivity,
        blast_radius=br, irreversible_effects=irr, is_cross_domain=cross,
        compute_cost=cost, irreversibility_score=irr_s, blast_radius_score=br_s,
        sensitivity_score=se_s,
    )
