function buildCard(result) {
  var score       = result.score;
  var verdict     = result.verdict;
  var label       = result.verdict_label;
  var explanation = result.explanation;
  var signals     = result.signals || [];

  var color = verdict === "safe" ? "#34a853"
            : verdict === "suspicious" ? "#fbbc04"
            : "#ea4335";

  var icon = verdict === "safe" ? "✅"
           : verdict === "suspicious" ? "⚠️"
           : "🚨";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Score")
        .setSubtitle("Powered by AI analysis")
    );

  // Score section
  var scoreSection = CardService.newCardSection();
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("VERDICT")
      .setText(icon + "  " + label)
      .setBottomLabel("Score: " + score + " / 100")
      .setWrapText(false)
  );
  card.addSection(scoreSection);

  // Explanation section
  var explanationSection = CardService.newCardSection()
    .setHeader("Analysis");
  explanationSection.addWidget(
    CardService.newTextParagraph().setText(explanation)
  );
  card.addSection(explanationSection);

  // Signals section
  if (signals.length > 0) {
    var signalSection = CardService.newCardSection()
      .setHeader("Detected Signals")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(3);

    signals.forEach(function(signal) {
      var severityIcon = signal.severity === "high" ? "🔴"
                       : signal.severity === "medium" ? "🟡"
                       : "🟢";
      signalSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(severityIcon + " " + signal.severity.toUpperCase())
          .setText(signal.description)
          .setWrapText(true)
      );
    });

    card.addSection(signalSection);
  }

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
