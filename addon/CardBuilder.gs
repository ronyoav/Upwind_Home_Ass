var _SIGNAL_GROUPS = {
  "Headers & Sender": [
    "spf_fail", "spf_missing", "dkim_fail", "dkim_missing", "dmarc_fail",
    "reply_to_mismatch", "lookalike_domain", "display_name_spoofing"
  ],
  "Content": [
    "urgency_language", "credential_phishing", "financial_lure", "threat_language"
  ],
  "Links & URLs": [
    "url_shortener", "suspicious_tld", "ip_url", "http_url",
    "known_bad_domain", "link_text_mismatch"
  ],
  "Attachments": [
    "dangerous_attachment", "suspicious_attachment"
  ],
  "AI Analysis": [
    "llm_intent", "llm_impersonation", "llm_urgency", "llm_suspicious_elements"
  ]
};

function _buildProgressBar(score) {
  var filled = Math.round(score / 100 * 15);
  var empty  = 15 - filled;
  return "█".repeat(filled) + "░".repeat(empty) + "  " + score + " / 100";
}

function _groupSignals(signals) {
  var grouped = {};
  var ungrouped = [];

  signals.forEach(function(signal) {
    var placed = false;
    for (var group in _SIGNAL_GROUPS) {
      if (_SIGNAL_GROUPS[group].indexOf(signal.type) !== -1) {
        if (!grouped[group]) grouped[group] = [];
        grouped[group].push(signal);
        placed = true;
        break;
      }
    }
    if (!placed) ungrouped.push(signal);
  });

  return { grouped: grouped, ungrouped: ungrouped };
}

function _groupIcon(signals) {
  var hasHigh   = signals.some(function(s) { return s.severity === "high"; });
  var hasMedium = signals.some(function(s) { return s.severity === "medium"; });
  return hasHigh ? "🔴" : hasMedium ? "🟡" : "🟢";
}

function buildCard(result) {
  var score       = result.score;
  var verdict     = result.verdict;
  var label       = result.verdict_label;
  var explanation = result.explanation;
  var signals     = result.signals || [];

  var verdictIcon = verdict === "safe" ? "✅"
                  : verdict === "suspicious" ? "⚠️"
                  : "🚨";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Score")
        .setSubtitle("Powered by AI analysis")
    );

  // Score + progress bar
  var scoreSection = CardService.newCardSection();
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("VERDICT")
      .setText(verdictIcon + "  " + label)
      .setBottomLabel(_buildProgressBar(score))
      .setWrapText(false)
  );
  card.addSection(scoreSection);

  // Grouped signals
  if (signals.length > 0) {
    var result = _groupSignals(signals);
    var grouped = result.grouped;

    for (var groupName in _SIGNAL_GROUPS) {
      var groupSignals = grouped[groupName];
      if (!groupSignals || groupSignals.length === 0) continue;

      var groupIcon    = _groupIcon(groupSignals);
      var groupSection = CardService.newCardSection()
        .setHeader(groupIcon + "  " + groupName)
        .setCollapsible(true)
        .setNumUncollapsibleWidgets(groupSignals.length);

      groupSignals.forEach(function(signal) {
        var severityIcon = signal.severity === "high" ? "🔴"
                         : signal.severity === "medium" ? "🟡"
                         : "🟢";
        groupSection.addWidget(
          CardService.newDecoratedText()
            .setTopLabel(severityIcon + " " + signal.severity.toUpperCase())
            .setText(signal.description)
            .setWrapText(true)
        );
      });

      card.addSection(groupSection);
    }
  }

  // Explanation
  var explanationSection = CardService.newCardSection()
    .setHeader("💬 What does this mean?")
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(1);
  explanationSection.addWidget(
    CardService.newTextParagraph().setText(explanation)
  );
  card.addSection(explanationSection);

  return card.build();
}

function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Analysis Failed")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph()
          .setText("Could not analyze this email. Error: " + errorMessage)
      )
    )
    .build();
}
