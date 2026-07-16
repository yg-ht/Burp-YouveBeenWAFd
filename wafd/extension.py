"""Small Burp adapter around the testable WAF detection components."""

import json
import os
import re
import time
from threading import RLock, Thread, current_thread

from .assessment import AssessmentStore
from .burp_issue import WafScanIssue
from .config import Configuration
from .detector import ResponseDetector
from .fingerprint import build_fingerprint
from .overrides import CatalogueOverrides
from .probes import ProbeCatalogue, ProbePlanner
from .request_builder import ProbeRequestBuilder
from .rules import RuleCatalogue


class WafExtension(object):
    """Register the extension without importing Burp classes at module load."""

    NON_GET_TARGET_OPTIONS = (
        ("root", "Root path (/)"),
        ("selected", "Selected request path"),
    )
    RULE_GROUP_ORDER = (
        "Generic behavioural rules", "Cloudflare", "AWS WAF", "Azure WAF",
        "Google Cloud Armor", "ModSecurity / OWASP CRS", "F5", "Akamai",
        "Imperva", "FortiWeb", "Sucuri", "Fastly", "Barracuda", "Radware",
        "Other rules",
    )
    PROBE_GROUP_ORDER = (
        "SQL injection", "Cross-site scripting",
        "Path traversal, inclusion and SSRF",
        "Command, template and runtime markers",
        "Structured parsers and content types",
        "HTTP methods, protocol and encoding",
        "Multipart, cookies and headers",
        "Size and inspection boundaries",
        "Provider-specific profiles", "Other generic probes",
    )

    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.catalogue = None
        self.detector = None
        self.assessments = None
        self.probes = None
        self.overrides = CatalogueOverrides()
        self.request_builder = ProbeRequestBuilder()
        self.configuration = Configuration()
        self._panel = None
        # Context-menu probes run outside Swing and may overlap extension
        # unloading. Guard lifecycle state and worker bookkeeping together.
        self._worker_lock = RLock()
        self._context_probe_workers = set()
        self._extension_unloaded = False

    def registerExtenderCallbacks(self, callbacks):
        """Burp entry point; registration failures are reported to Burp output."""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WAF Detector")
        self.catalogue = self._load_default_catalogue()
        probe_catalogue = ProbeCatalogue.bundled()
        self._load_configuration()
        self._load_catalogue_overrides()
        self.overrides.apply(self.catalogue.rules, probe_catalogue.probes)
        # The adapter owns Burp objects; the detector, scorer and planner stay
        # independent so their behaviour can be tested under CPython.
        self.detector = ResponseDetector(self.catalogue)
        self.assessments = AssessmentStore(self.catalogue.rules, self.configuration.threshold)
        # Non-GET probe profiles are permitted only when their catalogue entry
        # explicitly allows the method; the target policy controls the path.
        self.probes = ProbePlanner(self.configuration.max_probes, probe_catalogue)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("WAF Detector loaded with %d rules" % len(self.catalogue.rules))

    def extensionUnloaded(self):
        """Stop queued probe work when Burp unloads this extension instance."""
        with self._worker_lock:
            # Python/Jython threads cannot safely be killed. Workers check this
            # flag before and between requests, allowing an in-flight Burp call
            # to finish while preventing the remainder of its probe batch.
            self._extension_unloaded = True

    def _is_extension_unloaded(self):
        """Return the extension lifecycle state under its worker lock."""
        with self._worker_lock:
            return self._extension_unloaded

    def _load_default_catalogue(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            "data", "default_rules.json")
        with open(path, "r") as source:
            return RuleCatalogue.from_json(source.read())

    def _load_configuration(self):
        saved = self.callbacks.loadExtensionSetting("configuration")
        if saved:
            try:
                self.configuration = Configuration.from_json(saved)
            except (ValueError, TypeError):
                # Continue with validated defaults instead of preventing the
                # extension from loading because a saved setting is stale.
                self.callbacks.printError("WAF Detector ignored invalid saved configuration")

    def _load_catalogue_overrides(self):
        saved = self.callbacks.loadExtensionSetting("catalogue_overrides")
        if saved:
            try:
                self.overrides = CatalogueOverrides.from_json(saved)
            except (ValueError, TypeError):
                # Invalid local settings must not prevent the bundled
                # catalogues from loading with their declared defaults.
                self.callbacks.printError("WAF Detector ignored invalid catalogue overrides")

    def save_configuration(self):
        self.callbacks.saveExtensionSetting("configuration", self.configuration.to_json())

    def save_catalogue_overrides(self):
        self.overrides = CatalogueOverrides.capture(
            self.catalogue.rules, self.probes.catalogue.probes)
        self.callbacks.saveExtensionSetting(
            "catalogue_overrides", self.overrides.to_json())

    @classmethod
    def _non_get_target_label(cls, stored_value):
        """Return a descriptive UI label for a persisted target policy."""
        for value, label in cls.NON_GET_TARGET_OPTIONS:
            if stored_value == value:
                return label
        raise ValueError("unsupported non-GET target policy")

    @classmethod
    def _non_get_target_value(cls, display_label):
        """Return the stable persisted value behind a target-policy label."""
        for value, label in cls.NON_GET_TARGET_OPTIONS:
            if display_label == label:
                return value
        raise ValueError("unsupported non-GET target selection")

    @staticmethod
    def _tab_content_width(preferred_width=None):
        """Return a natural content width capped at the readable UI maximum."""
        maximum_width = 1260
        if preferred_width is None:
            return maximum_width
        return max(0, min(int(preferred_width), maximum_width))

    @staticmethod
    def _tab_content_spacer_weights():
        """Return equal GridBag weights used to centre bounded tab content."""
        return 1.0, 1.0

    @staticmethod
    def _rule_group(rule):
        """Return a stable provider or generic section for a detection rule."""
        provider_groups = (
            ("cloudflare", "Cloudflare"), ("aws-waf", "AWS WAF"),
            ("azure-waf", "Azure WAF"),
            ("google-cloud-armor", "Google Cloud Armor"),
            ("modsecurity", "ModSecurity / OWASP CRS"), ("f5", "F5"),
            ("akamai", "Akamai"), ("imperva", "Imperva"),
            ("fortiweb", "FortiWeb"), ("sucuri", "Sucuri"),
            ("fastly", "Fastly"), ("barracuda", "Barracuda"),
            ("radware", "Radware"),
        )
        tags = set(str(tag).lower() for tag in rule.tags)
        for provider_tag, label in provider_groups:
            if provider_tag in tags:
                return label
        if "generic" in tags:
            return "Generic behavioural rules"
        return "Other rules"

    @staticmethod
    def _probe_group(probe):
        """Return a stable functional section for an active probe."""
        identifier = str(probe.probe_id).lower()
        # Matrix and generic probes may list providers whose products commonly
        # inspect that input.  Only the explicit vendor diagnostic profiles
        # belong in the provider section; association metadata must not swallow
        # functional SQL/XSS/parser groups.
        provider_prefixes = (
            "cloudflare.", "aws.", "azure.", "google.", "modsecurity.",
            "f5.", "akamai.", "imperva.", "fortiweb.",
        )
        if identifier.startswith(provider_prefixes):
            return "Provider-specific profiles"
        groups = (
            (("matrix.sqli.", "generic.sqli"), "SQL injection"),
            (("matrix.xss.", "generic.xss", "generic.angle-encoding",
              "generic.json-script-fragment"), "Cross-site scripting"),
            (("matrix.absolute-path.", "generic.traversal", "generic.lfi",
              "generic.rfi", "generic.ssrf"),
             "Path traversal, inclusion and SSRF"),
            (("matrix.command-markers.", "matrix.php-markers.",
              "generic.command", "generic.template", "generic.el-marker",
              "generic.php", "generic.java-serialisation"),
             "Command, template and runtime markers"),
            (("matrix.content-type.", "matrix.graphql-query.",
              "matrix.xml-safe-entity.", "generic.graphql",
              "generic.xml-safe-entity"), "Structured parsers and content types"),
            (("matrix.hpp.", "matrix.parameter-name.", "matrix.protocol-input.",
              "matrix.query-structure.", "matrix.http-method.",
              "generic.rate-limit", "generic.crlf", "generic.invalid-percent",
              "generic.empty-value"), "HTTP methods, protocol and encoding"),
            (("matrix.multipart.", "matrix.cookie-behaviour.",
              "generic.multipart", "generic.header", "generic.cookie"),
             "Multipart, cookies and headers"),
            (("matrix.size-boundary.", "matrix.inspection-boundary."),
             "Size and inspection boundaries"),
        )
        for prefixes, label in groups:
            if identifier.startswith(prefixes):
                return label
        return "Other generic probes"

    @staticmethod
    def _group_catalogue_rows(rows, group_getter, group_order):
        """Return all rows bucketed in a declared, deterministic order."""
        buckets = {}
        for item, checkbox in rows:
            label = group_getter(item)
            buckets.setdefault(label, []).append((item, checkbox))
        grouped = []
        for label in group_order:
            if label in buckets:
                grouped.append((label, buckets.pop(label)))
        # Unknown future categories remain visible rather than being dropped.
        for label in sorted(buckets):
            grouped.append((label, buckets[label]))
        return grouped

    @staticmethod
    def _matches_catalogue_filter(values, query):
        """Return whether every whitespace-delimited term occurs in a row."""
        # Multiple terms narrow a large catalogue predictably without adding a
        # query language that users would need to learn.  Empty searches show
        # every entry.
        terms = [term for term in str(query or "").lower().split() if term]
        searchable = " ".join(str(value) for value in values
                              if value is not None).lower()
        return all(term in searchable for term in terms)

    @staticmethod
    def _rule_search_values(rule):
        """Return all rule metadata exposed through the catalogue filter."""
        return ((rule.name, rule.rule_id, rule.evidence_group) +
                tuple(rule.tags))

    @staticmethod
    def _probe_search_values(probe):
        """Return probe identity, classification, and request metadata."""
        profile = probe.profile or {}
        return ((probe.name, probe.probe_id) + tuple(probe.providers) +
                tuple(probe.actions) + tuple(probe.safe_methods) +
                (profile.get("method"), profile.get("placement"),
                 profile.get("content_type"), profile.get("classification")))

    @classmethod
    def _filter_catalogue_rows(cls, rows, query, value_getter):
        """Update checkbox visibility and return the number of matching rows."""
        visible = 0
        for item, checkbox in rows:
            matches = cls._matches_catalogue_filter(value_getter(item), query)
            checkbox.setVisible(matches)
            if matches:
                visible += 1
        return visible

    @staticmethod
    def _set_visible_catalogue_rows(rows, selected):
        """Change only rows currently visible through a catalogue filter."""
        changed = 0
        for unused_item, checkbox in rows:
            if checkbox.isVisible():
                checkbox.setSelected(bool(selected))
                changed += 1
        return changed

    # IExtensionTab -----------------------------------------------------
    def getTabCaption(self):
        return "WAF Detector"

    def getUiComponent(self):
        if self._panel is None:
            try:
                from java.awt import (BorderLayout, Dimension, FlowLayout,
                                      GridBagConstraints, GridBagLayout, Insets)
                from javax.swing import (BorderFactory, Box, BoxLayout, JButton,
                                         JCheckBox, JComboBox, JLabel, JPanel,
                                         JScrollPane, JTabbedPane, JTextField,
                                         JToggleButton, SwingConstants)
                self._panel = JPanel()
                self._panel.setLayout(BorderLayout())

                # Keep settings and the two large catalogues separate so the
                # complete 200+ probe set remains practical to navigate.
                tabs = JTabbedPane()
                tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

                def bounded_tab_content(component):
                    # GridBagLayout ignores a component's maximum width when
                    # distributing surplus space.  Cap its preferred width and
                    # put equal weighted spacers around it so surplus viewport
                    # width centres the controls instead of stretching them.
                    preferred = component.getPreferredSize()
                    component.setPreferredSize(Dimension(
                        self._tab_content_width(preferred.width),
                        preferred.height))

                    # A zero minimum allows the column to shrink when Burp's
                    # viewport is narrower than the configured 1,260-pixel cap.
                    # Vertical weight and BOTH fill retain the existing full-
                    # height scrolling behaviour of each tab.
                    component.setMinimumSize(Dimension(0, 0))
                    wrapper = JPanel(GridBagLayout())

                    left_weight, right_weight = self._tab_content_spacer_weights()
                    left_spacer_constraints = GridBagConstraints()
                    left_spacer_constraints.gridx = 0
                    left_spacer_constraints.gridy = 0
                    left_spacer_constraints.weightx = left_weight
                    left_spacer_constraints.weighty = 1.0
                    left_spacer_constraints.fill = GridBagConstraints.BOTH
                    wrapper.add(JPanel(), left_spacer_constraints)

                    content_constraints = GridBagConstraints()
                    content_constraints.gridx = 1
                    content_constraints.gridy = 0
                    content_constraints.weighty = 1.0
                    content_constraints.fill = GridBagConstraints.BOTH
                    content_constraints.anchor = GridBagConstraints.NORTHWEST
                    wrapper.add(component, content_constraints)

                    right_spacer_constraints = GridBagConstraints()
                    right_spacer_constraints.gridx = 2
                    right_spacer_constraints.gridy = 0
                    right_spacer_constraints.weightx = right_weight
                    right_spacer_constraints.weighty = 1.0
                    right_spacer_constraints.fill = GridBagConstraints.BOTH
                    wrapper.add(JPanel(), right_spacer_constraints)
                    return wrapper

                def add_bounded_tab(title, component):
                    tabs.addTab(title, bounded_tab_content(component))

                # Place each settings group at its preferred height.  The old
                # single GridLayout filled the complete viewport and stretched
                # text fields to many times the active font height.
                settings_panel = JPanel()
                settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
                settings_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

                setting_rows = {}

                def settings_group(title):
                    group = JPanel(GridBagLayout())
                    group.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createTitledBorder(title),
                        BorderFactory.createEmptyBorder(4, 6, 6, 6)))
                    group.setAlignmentX(0.0)
                    setting_rows[id(group)] = 0
                    return group

                def add_setting(group, caption, component):
                    row = setting_rows[id(group)]
                    label = JLabel(caption)
                    label.setLabelFor(component)

                    # Neither component fills vertically.  GridBag allocates
                    # the active look-and-feel's preferred font-relative height
                    # even when Burp gives the enclosing tab substantial room.
                    label_constraints = GridBagConstraints()
                    label_constraints.gridx = 0
                    label_constraints.gridy = row
                    label_constraints.anchor = GridBagConstraints.WEST
                    label_constraints.insets = Insets(2, 2, 2, 10)
                    group.add(label, label_constraints)

                    control_constraints = GridBagConstraints()
                    control_constraints.gridx = 1
                    control_constraints.gridy = row
                    control_constraints.weightx = 1.0
                    control_constraints.fill = GridBagConstraints.HORIZONTAL
                    control_constraints.anchor = GridBagConstraints.WEST
                    control_constraints.insets = Insets(2, 2, 2, 2)
                    group.add(component, control_constraints)
                    setting_rows[id(group)] = row + 1

                def finish_settings_group(group):
                    # A weighted empty row consumes any unexpected surplus
                    # height; real controls above it retain preferred heights.
                    filler = GridBagConstraints()
                    filler.gridx = 0
                    filler.gridy = setting_rows[id(group)]
                    filler.gridwidth = 2
                    filler.weighty = 1.0
                    filler.fill = GridBagConstraints.VERTICAL
                    group.add(Box.createVerticalGlue(), filler)

                detection_settings = settings_group("Detection")
                enabled = JCheckBox("Enabled", self.configuration.enabled)
                add_setting(detection_settings, "Passive monitoring", enabled)
                in_scope_only = JCheckBox("In-scope only", self.configuration.in_scope_only)
                add_setting(detection_settings,
                            "Restrict passive monitoring to Burp scope", in_scope_only)
                threshold = JTextField(str(self.configuration.threshold))
                add_setting(detection_settings, "WAF confidence threshold (0-1)", threshold)
                finish_settings_group(detection_settings)
                settings_panel.add(detection_settings)
                settings_panel.add(Box.createVerticalStrut(6))

                active_settings = settings_group("Active probing")
                max_probes = JTextField("" if self.configuration.max_probes is None else
                                        str(self.configuration.max_probes))
                add_setting(active_settings,
                            "Maximum probe requests (blank = unlimited)", max_probes)
                non_get_target = JComboBox()
                for unused_value, display_label in self.NON_GET_TARGET_OPTIONS:
                    non_get_target.addItem(display_label)
                non_get_target.setSelectedItem(
                    self._non_get_target_label(self.configuration.non_get_target))
                target_help = (
                    "<html><b>Root path (/):</b> send constructed non-GET probes to /."
                    "<br><b>Selected request path:</b> preserve the path selected for "
                    "active scanning.</html>")
                non_get_target.setToolTipText(target_help)
                non_get_target.getAccessibleContext().setAccessibleDescription(target_help)
                add_setting(active_settings, "Path for constructed non-GET probes",
                            non_get_target)
                finish_settings_group(active_settings)
                settings_panel.add(active_settings)
                settings_panel.add(Box.createVerticalStrut(6))

                size_settings = settings_group("Size and inspection limits")
                body_threshold = JTextField(str(self.configuration.body_test_threshold))
                add_setting(size_settings, "Request-body test threshold (bytes)",
                            body_threshold)
                header_threshold = JTextField(str(self.configuration.header_test_threshold))
                add_setting(size_settings, "Header-size test threshold (bytes)",
                            header_threshold)
                header_count_threshold = JTextField(
                    str(self.configuration.header_count_test_threshold))
                add_setting(size_settings, "Header-count test threshold",
                            header_count_threshold)
                inspection_boundary = JTextField(str(self.configuration.inspection_boundary))
                add_setting(size_settings, "Body inspection boundary (bytes)",
                            inspection_boundary)
                size_hard_max = JTextField(str(self.configuration.size_hard_max))
                add_setting(size_settings, "Hard maximum generated size (bytes)",
                            size_hard_max)
                finish_settings_group(size_settings)
                settings_panel.add(size_settings)

                # BorderLayout.NORTH prevents BoxLayout from distributing spare
                # viewport height between otherwise compact settings groups.
                settings_view = JPanel()
                settings_view.setLayout(BorderLayout())
                settings_view.add(settings_panel, BorderLayout.NORTH)
                add_bounded_tab("Settings", JScrollPane(settings_view))

                rule_checkboxes = []
                for rule in self.catalogue.rules:
                    # Rule enablement is deliberately user-selectable because
                    # fingerprints and acceptable false-positive rates vary by
                    # engagement.
                    checkbox = JCheckBox("%s [%s] (weight %.0f)" %
                                         (rule.name, rule.rule_id, rule.weight), rule.enabled)
                    rule_checkboxes.append((rule, checkbox))

                probe_checkboxes = []
                for probe in self.probes.catalogue.probes:
                    method = str(probe.profile.get("method", "/".join(probe.safe_methods)))
                    placement = str(probe.profile.get("placement", "insertion point"))
                    checkbox = JCheckBox("%s [%s] (%s, %s)" %
                                         (probe.name, probe.probe_id, method, placement),
                                         probe.enabled)
                    probe_checkboxes.append((probe, checkbox))

                def catalogue_tab(rows, value_getter, group_getter, group_order,
                                  filter_description):
                    tab = JPanel()
                    tab.setLayout(BorderLayout(0, 6))
                    tab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

                    controls = JPanel()
                    controls.setLayout(BoxLayout(controls, BoxLayout.Y_AXIS))
                    filter_controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
                    group_controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
                    filter_controls.setAlignmentX(0.0)
                    group_controls.setAlignmentX(0.0)
                    filter_label = JLabel("Filter")
                    filter_text = JTextField(24)
                    filter_text.setToolTipText(filter_description)
                    filter_label.setLabelFor(filter_text)
                    apply_filter = JButton("Apply")
                    clear_filter = JButton("Show all")
                    expand_all = JButton("Expand all")
                    collapse_all = JButton("Collapse all")
                    enable_visible = JButton("Enable matches")
                    disable_visible = JButton("Disable matches")
                    visible_count = JLabel("%d of %d matched" % (len(rows), len(rows)))
                    for component in (filter_label, filter_text, apply_filter,
                                      clear_filter, visible_count):
                        filter_controls.add(component)
                    for component in (expand_all, collapse_all, enable_visible,
                                      disable_visible):
                        group_controls.add(component)
                    controls.add(filter_controls)
                    controls.add(group_controls)
                    tab.add(controls, BorderLayout.NORTH)

                    # Each functional/provider group starts collapsed so the
                    # tab presents a navigable overview rather than hundreds of
                    # uninterrupted checkboxes.
                    rows_panel = JPanel()
                    rows_panel.setLayout(BoxLayout(rows_panel, BoxLayout.Y_AXIS))
                    grouped_rows = self._group_catalogue_rows(
                        rows, group_getter, group_order)
                    group_sections = []

                    def set_group_expanded(section, expanded):
                        label, group_rows, unused_container, toggle, content = section
                        toggle.setSelected(bool(expanded))
                        content.setVisible(bool(expanded))
                        marker = "[-]" if expanded else "[+]"
                        matched = sum(1 for unused_item, checkbox in group_rows
                                      if checkbox.isVisible())
                        count = ("%d/%d" % (matched, len(group_rows))
                                 if matched != len(group_rows) else str(len(group_rows)))
                        toggle.setText("%s %s (%s)" % (marker, label, count))

                    def make_toggle_listener(section):
                        def toggle_group(event):
                            set_group_expanded(section, section[3].isSelected())
                            rows_panel.revalidate()
                            rows_panel.repaint()
                        return toggle_group

                    for label, group_rows in grouped_rows:
                        group_panel = JPanel()
                        group_panel.setLayout(BorderLayout())
                        group_panel.setAlignmentX(0.0)
                        group_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0))
                        toggle = JToggleButton("[+] %s (%d)" % (label, len(group_rows)))
                        toggle.setHorizontalAlignment(SwingConstants.LEFT)
                        content = JPanel()
                        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
                        content.setBorder(BorderFactory.createEmptyBorder(2, 18, 4, 4))
                        for unused_item, checkbox in group_rows:
                            checkbox.setAlignmentX(0.0)
                            content.add(checkbox)
                        content.setVisible(False)
                        group_panel.add(toggle, BorderLayout.NORTH)
                        group_panel.add(content, BorderLayout.CENTER)
                        rows_panel.add(group_panel)
                        section = (label, group_rows, group_panel, toggle, content)
                        group_sections.append(section)
                        toggle.addActionListener(make_toggle_listener(section))

                    rows_view = JPanel()
                    rows_view.setLayout(BorderLayout())
                    rows_view.add(rows_panel, BorderLayout.NORTH)
                    tab.add(JScrollPane(rows_view), BorderLayout.CENTER)

                    def refresh_filter(event=None):
                        shown = self._filter_catalogue_rows(
                            rows, filter_text.getText(), value_getter)
                        visible_count.setText("%d of %d matched" % (shown, len(rows)))
                        filtering = bool(str(filter_text.getText()).strip())
                        for section in group_sections:
                            group_matches = any(checkbox.isVisible()
                                                for unused_item, checkbox in section[1])
                            section[2].setVisible(group_matches)
                            # Search results should be immediately visible;
                            # outside a search the user's expansion state stays.
                            if filtering and group_matches:
                                set_group_expanded(section, True)
                            else:
                                set_group_expanded(section, section[3].isSelected())
                        rows_panel.revalidate()
                        rows_panel.repaint()

                    def set_all_groups(expanded):
                        for section in group_sections:
                            if section[2].isVisible():
                                set_group_expanded(section, expanded)
                        rows_panel.revalidate()
                        rows_panel.repaint()

                    def show_all(event):
                        filter_text.setText("")
                        refresh_filter()
                        set_all_groups(False)

                    def select_visible(selected):
                        def apply_selection(event):
                            self._set_visible_catalogue_rows(rows, selected)
                        return apply_selection

                    # Enter applies the filter without requiring mouse use.
                    filter_text.addActionListener(refresh_filter)
                    apply_filter.addActionListener(refresh_filter)
                    clear_filter.addActionListener(show_all)
                    expand_all.addActionListener(lambda event: set_all_groups(True))
                    collapse_all.addActionListener(lambda event: set_all_groups(False))
                    enable_visible.addActionListener(select_visible(True))
                    disable_visible.addActionListener(select_visible(False))
                    return tab

                add_bounded_tab("Detection Rules", catalogue_tab(
                    rule_checkboxes, self._rule_search_values, self._rule_group,
                    self.RULE_GROUP_ORDER,
                    "Match rule name, ID, evidence group, or tag"))
                add_bounded_tab("Active Probes", catalogue_tab(
                    probe_checkboxes, self._probe_search_values, self._probe_group,
                    self.PROBE_GROUP_ORDER,
                    "Match probe name, ID, provider, action, method, placement, or content type"))
                self._panel.add(tabs, BorderLayout.CENTER)

                save = JButton("Save settings")
                def save_settings(event):
                    try:
                        # Build and validate a complete replacement before
                        # mutating any live detector or catalogue state.
                        maximum_text = str(max_probes.getText()).strip()
                        candidate = Configuration(
                            threshold.getText(), in_scope_only.isSelected(),
                            None if not maximum_text else int(maximum_text),
                            enabled.isSelected(), self._non_get_target_value(
                                str(non_get_target.getSelectedItem())),
                            int(body_threshold.getText()), int(header_threshold.getText()),
                            int(header_count_threshold.getText()),
                            int(inspection_boundary.getText()), int(size_hard_max.getText()))
                        self.configuration = candidate
                        for rule, checkbox in rule_checkboxes:
                            rule.enabled = checkbox.isSelected()
                        for probe, checkbox in probe_checkboxes:
                            probe.enabled = checkbox.isSelected()
                        self.assessments.engine.threshold = self.configuration.threshold
                        self.probes.max_probes = self.configuration.max_probes
                        self._discard_disabled_evidence()
                        self.save_configuration()
                        self.save_catalogue_overrides()
                        self.callbacks.printOutput("WAF Detector settings saved")
                    except (ValueError, TypeError) as error:
                        self.callbacks.printError("WAF Detector settings not saved: %s" % error)
                save.addActionListener(save_settings)
                actions = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 4))
                actions.add(save)
                self._panel.add(actions, BorderLayout.SOUTH)
            except ImportError:  # Allows the adapter to be imported by tests.
                self._panel = object()
        return self._panel

    def _discard_disabled_evidence(self):
        """Remove observations disabled by the user's current catalogue choices."""
        enabled_rules = set(rule.rule_id for rule in self.catalogue.rules if rule.enabled)
        enabled_probes = set(probe.probe_id for probe in self.probes.catalogue.probes
                             if probe.enabled)
        for assessment in self.assessments.assessments.values():
            assessment.evidence = [
                item for item in assessment.evidence
                if item.rule_id in enabled_rules and
                (not item.characteristic or item.characteristic in enabled_probes)
            ]

    # IHttpListener ----------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Analyse responses only, bounded to Burp's configured scope."""
        if (not self.configuration.enabled or messageIsRequest or
                self._is_extension_traffic(toolFlag)):
            return
        try:
            request = self.helpers.analyzeRequest(messageInfo)
            url = request.getUrl()
            if self.configuration.in_scope_only and not self.callbacks.isInScope(url):
                return
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            response = self._normalise_response(messageInfo.getResponse(), response_info)
            origin = self._origin(url)
            evidence = self.detector.detect(origin, response)
            self.assessments.observe(origin, evidence, messageInfo)
            self._publish_issue(origin)
        except Exception as error:
            # A malformed message must not disrupt Burp's traffic processing.
            self.callbacks.printError("WAF Detector passive analysis failed: %s" % error)

    def _is_extension_traffic(self, tool_flag):
        return getattr(self.callbacks, "TOOL_EXTENDER", object()) == tool_flag

    def _normalise_response(self, raw_response, response_info, elapsed_ms=None):
        # Legacy Burp normally exposes response headers as strings, while test
        # adapters and alternative wrappers may expose name/value objects.
        # Accept both forms and skip the status line deterministically.
        headers = {}
        status_line = ""
        for header in response_info.getHeaders():
            if hasattr(header, "getName") and hasattr(header, "getValue"):
                name = str(header.getName()).lower()
                value = str(header.getValue())
            else:
                text = str(header)
                if ":" not in text:
                    if text.upper().startswith("HTTP/"):
                        status_line = text
                    continue
                name, value = text.split(":", 1)
                name, value = name.strip().lower(), value.strip()
            if not name:
                continue
            # Preserve repeated response headers in one deterministic value;
            # Set-Cookie parsing needs every occurrence to observe mitigation
            # and session rotation without retaining cookie secrets.
            headers[name] = (headers[name] + "\n" + value) if name in headers else value
        body = raw_response[response_info.getBodyOffset():]
        if not isinstance(body, str) and self.helpers is not None and hasattr(
                self.helpers, "bytesToString"):
            body = str(self.helpers.bytesToString(body))
        elif not isinstance(body, str) and hasattr(body, "decode"):
            body = body.decode("utf-8", "replace")
        elif not isinstance(body, str):
            body = str(body)
        first_line = status_line
        if not first_line and hasattr(raw_response, "splitlines"):
            first_line = raw_response.splitlines()[0] if raw_response.splitlines() else ""
        if hasattr(first_line, "decode"):
            first_line = first_line.decode("iso-8859-1", "replace")
        # Preserve HTTP/1.0, HTTP/1.1 and HTTP/2 for protocol-differential
        # rules without relying on Burp-specific response objects downstream.
        match = re.match(r"HTTP/(\d(?:\.\d)?)", str(first_line))
        return build_fingerprint(response_info.getStatusCode(), headers, body[:1024 * 1024],
                                 match.group(1) if match else "", elapsed_ms=elapsed_ms)

    @staticmethod
    def _origin(url):
        protocol = str(url.getProtocol()).lower()
        host = str(url.getHost()).lower()
        if ":" in host and not host.startswith("["):
            # URL authorities require brackets around an IPv6 literal.
            host = "[%s]" % host
        port = int(url.getPort())
        if port < 0:
            # Explicit ports keep assessments for different services separate,
            # including when java.net.URL omits the scheme's default port.
            port = 443 if protocol == "https" else 80
        return "%s://%s:%d" % (protocol, host, port)

    def _publish_issue(self, origin):
        """Publish a replaceable current assessment for one origin."""
        assessment = self.assessments.assessments[origin]
        representative = assessment.representative_message
        if representative is None:
            # A legacy IScanIssue requires a concrete URL and HTTP service.
            # Observations normally provide one; avoid inventing Java objects
            # if an internal caller creates an assessment without a message.
            return
        score = self.assessments.engine.score(assessment.evidence)[0]
        confidence = "Certain" if score >= 0.85 else ("Firm" if score >= 0.60 else "Tentative")
        suspected = score >= self.assessments.engine.threshold
        # Under the organisation's testing policy, a suspected WAF is a
        # high-severity engagement blocker rather than an informational note.
        severity = "High" if suspected else "Information"
        remediation = (
            "Stop active testing and confirm that the target is approved under "
            "the organisation's no-WAF testing policy before continuing."
            if suspected else
            "Continue monitoring traffic and validate the suspected product manually.")
        # Burp replaces earlier issues with the same identity via
        # consolidateDuplicateIssues(), leaving one current assessment.
        issue = WafScanIssue(
            self._issue_url(origin, representative),
            representative.getHttpService(), self.assessments.detail(origin),
            remediation, severity, confidence, [representative])
        self.callbacks.addScanIssue(issue)

    def _issue_url(self, origin, representative):
        """Return a stable origin URL, falling back outside the Jython runtime."""
        try:
            from java.net import URL
            return URL(origin)
        except ImportError:  # CPython adapter tests do not provide java.net.
            return self.helpers.analyzeRequest(representative).getUrl()

    # IScannerCheck ----------------------------------------------------
    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Run enabled probe profiles for a requested Scanner insertion point."""
        try:
            if self._is_extension_unloaded():
                return []
            request_info = self.helpers.analyzeRequest(baseRequestResponse)
            name = insertionPoint.getInsertionPointName()
            probe_entries = self.probes.plan_entries(request_info.getMethod(), name)
            method = str(request_info.getMethod()).upper()
            root_mode = (method not in ("GET", "HEAD", "OPTIONS") and
                         self.configuration.non_get_target == "root")
            control = baseRequestResponse
            base_headers = list(request_info.getHeaders())
            root_headers = list(base_headers)
            if root_mode:
                # By default, non-GET probes target / rather than replaying a
                # selected application action. The method is retained, while
                # the body is replaced with the configured probe marker.
                root_headers[0] = "%s / HTTP/1.1" % method
                control_request = self.helpers.buildHttpMessage(root_headers, "")
                control, unused_state, unused_elapsed = self._send_active_request(
                    baseRequestResponse.getHttpService(), control_request)
                if self._is_extension_unloaded():
                    return []
                if control is None or control.getResponse() is None:
                    # Falling back preserves scan availability, but means the
                    # selected response is the control for this comparison.
                    control = baseRequestResponse
            results = []
            specialised_controls = {}
            observed = False
            origin = self._origin(request_info.getUrl())
            for probe in probe_entries:
                # Unloading is cooperative because Burp's legacy HTTP API does
                # not expose safe cancellation for an in-flight request.
                if self._is_extension_unloaded():
                    return []
                try:
                    if probe.profile.get("placement"):
                        # Specialist profiles construct both control and probe
                        # in the same wire format, changing only the logical
                        # value or an explicitly declared boundary offset.
                        original_body = baseRequestResponse.getRequest()[request_info.getBodyOffset():]
                        built = self.request_builder.build(
                            base_headers, original_body, probe.profile, probe.value,
                            self.configuration.non_get_target == "root",
                            self._probe_limits())
                        request = self.helpers.buildHttpMessage(
                            built.headers, self._request_body_bytes(built.body))
                        if probe.control_required:
                            control = specialised_controls.get(probe.probe_id)
                            if control is None:
                                control_value = probe.profile.get("control_value", "ordinary")
                                control_profile = dict(probe.profile)
                                control_profile.update(probe.profile.get("control_profile", {}))
                                built_control = self.request_builder.build(
                                    base_headers, original_body, control_profile, control_value,
                                    self.configuration.non_get_target == "root",
                                    self._probe_limits())
                                control_request = self.helpers.buildHttpMessage(
                                    built_control.headers,
                                    self._request_body_bytes(built_control.body))
                                control_request = self._apply_probe_profile(
                                    control_request, control_profile)
                                control, unused_state, unused_elapsed = self._send_active_request(
                                    baseRequestResponse.getHttpService(), control_request)
                                if self._is_extension_unloaded():
                                    return []
                                if control is None or control.getResponse() is None:
                                    control = baseRequestResponse
                                specialised_controls[probe.probe_id] = control
                        else:
                            control = baseRequestResponse
                    elif root_mode:
                        request = self.helpers.buildHttpMessage(
                            root_headers, probe.value.encode("utf-8"))
                    else:
                        request = insertionPoint.buildRequest(probe.value.encode("utf-8"))
                except (ValueError, TypeError) as error:
                    # One malformed local profile must not cancel every other
                    # explicitly enabled probe in the active operation.
                    self.callbacks.printError(
                        "WAF Detector skipped probe %s: %s" % (probe.probe_id, error))
                    continue
                try:
                    request = self._apply_probe_profile(request, probe.profile)
                except (ValueError, TypeError) as error:
                    self.callbacks.printError(
                        "WAF Detector skipped probe %s: %s" % (probe.probe_id, error))
                    continue
                response, connection_state, elapsed_ms = self._send_active_request(
                    baseRequestResponse.getHttpService(), request)
                if self._is_extension_unloaded():
                    return []
                if response is None or response.getResponse() is None:
                    # A reset/no-response outcome is itself behavioural
                    # evidence, but it must not be treated as HTTP status 0.
                    reset = {"status": 0, "headers": {}, "body": "",
                             "connection_state": connection_state,
                             "elapsed_ms": elapsed_ms}
                    evidence = self.detector.detect(
                        origin, reset, "active", characteristic=probe.probe_id,
                        classification=probe.profile.get("classification", ""))
                    self.assessments.observe(origin, evidence, baseRequestResponse)
                    observed = True
                    continue
                response_info = self.helpers.analyzeResponse(response.getResponse())
                normalised = self._normalise_response(
                    response.getResponse(), response_info, elapsed_ms)
                baseline = None
                control_response = control.getResponse() if control is not None else None
                if control_response is not None:
                    # Request-only selections and failed controls have no safe
                    # baseline to parse. Passing None deliberately disables
                    # differential rules while retaining response signatures.
                    baseline_info = self.helpers.analyzeResponse(control_response)
                    baseline = self._normalise_response(
                        control_response, baseline_info)
                evidence = self.detector.detect(
                    origin, normalised, "active", baseline, probe.probe_id,
                    probe.profile.get("classification", ""))
                self.assessments.observe(origin, evidence, response)
                observed = True
                results.append(response)
            if observed:
                # Publish once after the batch so a large matrix does not ask
                # Burp to replace the same issue hundreds of times.
                self._publish_issue(origin)
            return []
        except Exception as error:
            self.callbacks.printError("WAF Detector active probe failed: %s" % error)
            return []

    @staticmethod
    def _request_body_bytes(body):
        """Encode constructed text while preserving Burp/Java byte arrays."""
        return body.encode("utf-8") if hasattr(body, "encode") else body

    def _send_active_request(self, service, request):
        """Return ``(message, connection_state, elapsed_ms)`` for one request."""
        if self._is_extension_unloaded():
            return None, "cancelled", 0
        started = time.time()
        try:
            message = self.callbacks.makeHttpRequest(service, request)
            elapsed_ms = int((time.time() - started) * 1000)
            state = "complete" if message is not None and message.getResponse() is not None else "no-response"
            return message, state, elapsed_ms
        except Exception as error:
            elapsed_ms = int((time.time() - started) * 1000)
            text = str(error).lower()
            state = "timeout" if "timed out" in text or "timeout" in text else (
                "reset" if "reset" in text else "network-error")
            self.callbacks.printError("WAF Detector active request ended with %s: %s" %
                                      (state, error))
            return None, state, elapsed_ms

    def _probe_limits(self):
        """Expose only bounded size settings to the request builder."""
        return {
            "body_test_threshold": self.configuration.body_test_threshold,
            "header_test_threshold": self.configuration.header_test_threshold,
            "header_count_test_threshold": self.configuration.header_count_test_threshold,
            "inspection_boundary": self.configuration.inspection_boundary,
            "size_hard_max": self.configuration.size_hard_max,
        }

    def _apply_probe_profile(self, request, profile):
        """Apply only explicitly declared, non-authentication profile headers."""
        request_headers = profile.get("request_headers", {}) if profile else {}
        if profile and profile.get("accept"):
            request_headers = dict(request_headers)
            request_headers["Accept"] = profile["accept"]
        if not request_headers:
            return request
        for name, value in request_headers.items():
            if (not str(name) or ":" in str(name) or "\r" in str(name) or "\n" in str(name)
                    or "\r" in str(value) or "\n" in str(value)):
                raise ValueError("probe profile contains an invalid request header")
        info = self.helpers.analyzeRequest(request)
        headers = list(info.getHeaders())
        lowered = dict((str(key).lower(), value) for key, value in request_headers.items())
        updated = []
        seen = set()
        for header in headers:
            # Replace a declared header once while preserving all unrelated
            # request headers and the original body bytes.
            name = str(header).split(":", 1)[0].strip().lower()
            if name in lowered:
                updated.append("%s: %s" % (name, lowered[name]))
                seen.add(name)
            else:
                updated.append(str(header))
        for name, value in lowered.items():
            if name not in seen:
                updated.append("%s: %s" % (name, value))
        body = request[info.getBodyOffset():]
        return self.helpers.buildHttpMessage(updated, body)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # A new assessment contains the current evidence and supersedes the old.
        return 1

    # IContextMenuFactory ----------------------------------------------
    def createMenuItems(self, invocation):
        try:
            from javax.swing import JMenuItem
            messages = invocation.getSelectedMessages()
            if not messages:
                return []
            item = JMenuItem("Probe for WAF")
            # Swing invokes menu listeners on its event dispatch thread. Burp
            # rejects HTTP requests made on that UI thread, so schedule the
            # complete probe operation on a dedicated background thread.
            item.addActionListener(lambda event: self._start_selected_probe(messages[0]))
            return [item]
        except ImportError:
            return []

    def _start_selected_probe(self, message):
        """Schedule a context-menu probe away from Swing's UI thread."""
        worker = None
        try:
            if self._is_extension_unloaded():
                return
            # Persist request, response and service while still inside the
            # Swing callback. Editors such as Repeater may mutate their live
            # message object as soon as this callback returns.
            persisted_message = self.callbacks.saveBuffersToTempFiles(message)
            if persisted_message is None:
                raise ValueError("Burp did not return a persisted message")
            # Jython implements threading.Thread with a JVM thread, keeping
            # makeHttpRequest() off Swing's event dispatch thread while the
            # existing probe method retains responsibility for error logging.
            worker = Thread(
                target=self._run_selected_probe,
                args=(persisted_message,),
                name="WAF Detector active probe")
            # A background probe must not keep Burp's JVM alive during exit.
            worker.setDaemon(True)
            with self._worker_lock:
                if self._extension_unloaded:
                    return
                self._context_probe_workers.add(worker)
            worker.start()
        except Exception as error:
            if worker is not None:
                with self._worker_lock:
                    self._context_probe_workers.discard(worker)
            # Thread creation can fail under resource pressure or a restrictive
            # runtime; report that failure without falling back to the UI thread.
            self.callbacks.printError(
                "WAF Detector could not start context probe: %s" % error)

    def _run_selected_probe(self, message):
        """Run one persisted probe and release its worker bookkeeping."""
        try:
            if not self._is_extension_unloaded():
                self._probe_selected(message)
        finally:
            # Removing completed workers prevents the extension instance from
            # retaining thread objects for every context-menu invocation.
            with self._worker_lock:
                self._context_probe_workers.discard(current_thread())

    def _probe_selected(self, message):
        """Context-menu entry point; intentionally reuses Scanner behaviour."""
        try:
            request_info = self.helpers.analyzeRequest(message)
            extension = self
            class SelectedPoint(object):
                def getInsertionPointName(inner):
                    return "query"
                def buildRequest(inner, payload):
                    # Parse and rebuild the request line so the marker is added
                    # to the request target, never after the HTTP version.
                    headers = list(request_info.getHeaders())
                    encoded = extension.helpers.urlEncode(payload.decode("utf-8"))
                    headers[0] = extension._append_query_parameter(
                        headers[0], "wafd_probe", encoded)
                    body = message.getRequest()[request_info.getBodyOffset():]
                    return extension.helpers.buildHttpMessage(headers, body)
            self.doActiveScan(message, SelectedPoint())
        except Exception as error:
            self.callbacks.printError("WAF Detector context probe failed: %s" % error)

    @staticmethod
    def _append_query_parameter(request_line, name, encoded_value):
        """Append an encoded query parameter to a valid HTTP request target."""
        # Split only between the three request-line components and normalise
        # their separators when rebuilding the line.
        parts = str(request_line).split(None, 2)
        if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
            raise ValueError("request line must contain method, target and HTTP version")
        method, target, version = parts
        if target == "*" or method.upper() == "CONNECT":
            raise ValueError("request-target form does not support query parameters")
        if not version.upper().startswith("HTTP/"):
            raise ValueError("request line must end with an HTTP version")

        # Fragments are not normally present in HTTP request targets, but if a
        # client supplies one, keep it after the newly added query parameter.
        target_and_query, marker, fragment = target.partition("#")
        if target_and_query.endswith(("?", "&")):
            separator = ""
        else:
            separator = "&" if "?" in target_and_query else "?"
        updated_target = "%s%s%s=%s" % (
            target_and_query, separator, str(name), str(encoded_value))
        if marker:
            updated_target = "%s#%s" % (updated_target, fragment)
        return "%s %s %s" % (method, updated_target, version)
