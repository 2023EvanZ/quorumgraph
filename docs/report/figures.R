# Report figures from the CSVs docs/report/numbers.py writes (run that first).
#   Rscript docs/report/figures.R
suppressPackageStartupMessages(library(ggplot2))
setwd("docs/report")

wilson <- function(k, n, z = 1.959964) {
  p <- k / n; d <- 1 + z^2 / n; c <- (p + z^2 / (2 * n)) / d
  h <- z * sqrt(p * (1 - p) / n + z^2 / (4 * n^2)) / d
  data.frame(share = p, lo = pmax(0, c - h), hi = pmin(1, c + h))
}
pal <- c("#2a78d6", "#eb6834", "#1baf7a", "#eda100")  # validated (scripts/validate_palette.js, light)
ink <- "#3d3d3a"; muted <- "#8a8984"; grid <- "#e6e5e0"
pct <- function(x) paste0(round(100 * x), "%")
th <- theme_minimal(base_size = 10) +
  theme(panel.grid.major.x = element_blank(), panel.grid.minor = element_blank(),
        panel.grid.major.y = element_line(colour = grid, linewidth = 0.3),
        axis.text = element_text(colour = muted), axis.title.y = element_text(colour = muted, size = 9),
        strip.text = element_text(colour = ink, hjust = 0), legend.position = "top",
        legend.justification = "left", legend.text = element_text(colour = ink),
        legend.title = element_blank())
dodge <- position_dodge(width = 0.84, preserve = "single")  # bars keep their slot when a design has no data

# Figure: audit design
a <- read.csv("tables/fig_audit.csv", stringsAsFactors = FALSE)
a <- cbind(a, wilson(a$k, a$n))
a$design <- factor(a$design, levels = c("agents", "agents, lineage-weighted", "actions (gateway)", "actions (simulated)"),
                   labels = c("Agents, once per generation (real)", "Agents, lineage-weighted (real)",
                              "Actions, at the gateway (real)", "Actions, coin flip (simulated)"))
a$world <- factor(a$world, levels = c("revoke_only", "gated", "recursive_soft"),
                  labels = c("revoke_only (no gate)", "gated", "recursive_soft"))
a$cost <- factor(paste("transparency cost", a$cost))
p <- ggplot(a, aes(world, share, fill = design)) +
  geom_col(position = dodge, width = 0.8, colour = "white", linewidth = 0.4) +
  geom_errorbar(aes(ymin = lo, ymax = hi), position = dodge, width = 0.25, colour = ink, linewidth = 0.3) +
  facet_wrap(~cost) + scale_fill_manual(values = pal) +
  scale_y_continuous(labels = pct, limits = c(0, 1), expand = expansion(mult = c(0, 0.02))) +
  guides(fill = guide_legend(nrow = 2)) +
  labs(x = NULL, y = "Seeds collapsed (95% Wilson CI)") + th
ggsave("fig_audit.pdf", p, width = 6.5, height = 3.4)

# Figure: guards by drift type
g <- read.csv("tables/fig_guards.csv", stringsAsFactors = FALSE)
g <- cbind(g, wilson(g$k, g$n))
g$world <- factor(g$world, levels = c("gated", "no guard", "soft", "block"),
                  labels = c("gated (no promotion)", "no guard", "soft guard", "block guard"))
g$cond <- factor(g$cond, levels = c("Random, 0.2", "Random, 0.4", "Adversarial, 0.2", "Adversarial, 0.4"),
                 labels = c("Random drift 0.2", "Random drift 0.4", "Adversarial drift 0.2", "Adversarial drift 0.4"))
g$panel <- factor(g$panel, levels = c("collapsed", "captured"),
                  labels = c("Seeds collapsed (population mean defect > 0.5)",
                             "Trusted set captured (trusted mean defect > 0.5)"))
p <- ggplot(g, aes(cond, share, fill = world)) +
  geom_col(position = dodge, width = 0.8, colour = "white", linewidth = 0.4) +
  geom_errorbar(aes(ymin = lo, ymax = hi), position = dodge, width = 0.25, colour = ink, linewidth = 0.3) +
  facet_wrap(~panel, ncol = 1, scales = "free_y") + scale_fill_manual(values = pal) +
  scale_y_continuous(labels = pct, expand = expansion(mult = c(0, 0.05))) +
  labs(x = NULL, y = "Share of runs (95% Wilson CI)") + th
ggsave("fig_guards.pdf", p, width = 6.5, height = 4.6)
cat("wrote fig_audit.pdf, fig_guards.pdf\n")
