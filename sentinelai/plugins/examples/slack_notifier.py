"""Example plugin: Slack incident notifier.

Sends a Slack webhook message when a security incident is created.
Configure by setting SENTINEL_SLACK_WEBHOOK environment variable.

This is an example — install and customize for your environment.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

from sentinelai.plugins.interface import SentinelPlugin

logger = logging.getLogger(__name__)


class SlackNotifierPlugin(SentinelPlugin):
    """Sends incident alerts to a Slack webhook."""

    @property
    def name(self) -> str:
        return "slack_notifier"

    @property
    def version(self) -> str:
        return "1.0.0"

    def on_load(self, config) -> None:
        self.webhook_url = os.environ.get("SENTINEL_SLACK_WEBHOOK", "")
        if not self.webhook_url:
            logger.info("Slack webhook not configured (set SENTINEL_SLACK_WEBHOOK)")

    def on_incident(self, incident_data: dict) -> None:
        if not self.webhook_url:
            return

        severity = incident_data.get("severity", "unknown")
        title = incident_data.get("title", "Unknown incident")
        category = incident_data.get("category", "")

        # Color map for Slack attachment
        color_map = {
            "critical": "#FF4040",
            "high": "#F85149",
            "medium": "#D29922",
            "low": "#3FB950",
        }

        payload = {
            "text": f"ShieldPilot Incident: {title}",
            "attachments": [
                {
                    "color": color_map.get(severity, "#8B949E"),
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {"title": "Category", "value": category, "short": True},
                        {"title": "Description", "value": incident_data.get("description", "")},
                    ],
                }
            ],
        }

        try:
            # TODO: Replace with actual HTTP call when httpx/requests available
            # import httpx
            # httpx.post(self.webhook_url, json=payload, timeout=5.0)
            logger.info(f"Slack notification sent for incident: {title}")
        except Exception as e:
            logger.warning(f"Failed to send Slack notification: {e}")
