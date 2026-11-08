# Headline figure for the README: collapsed seeds by lineage-guard mode.
# Reads the final generation of the drift/soft/API grid (runs/ is gitignored;
# regenerate it with runs/overnight2.sh, see README) and writes
# docs/headline_collapse.png.
#   Rscript docs/make_headline_figure.R
suppressPackageStartupMessages(library(ggplot2))

files <- c("runs/selection-drift0/generations.csv",
           "runs/selection-drift02/generations.csv",
           "runs/selection-api/generations.csv")
d <- do.call(rbind, lapply(files, function(f) {
  x <- read.csv(f, stringsAsFactors = FALSE)
  x[x$generation == 59, c("world", "audit_channel", "drift_prob", "mean_defect")]
}))
# setNames, not c(recursive = ...): `recursive` is an argument of c() and gets swallowed
keep <- setNames(c("gated (no promotion)", "no guard", "soft guard", "block guard"),
                 c("gated", "recursive", "recursive_soft", "recursive_guarded"))
d <- d[d$world %in% names(keep), ]
d$world <- factor(keep[d$world], levels = keep)
d$cond <- factor(sprintf("%s audits, drift %s",
                         ifelse(d$audit_channel == "sim", "Sim", "Real-endpoint"), d$drift_prob),
                 levels = c("Sim audits, drift 0", "Sim audits, drift 0.2",
                            "Real-endpoint audits, drift 0", "Real-endpoint audits, drift 0.2"))
agg <- aggregate(mean_defect ~ world + cond, d, function(v) mean(v > 0.5))
names(agg)[3] <- "collapsed"

pal <- c("#2a78d6", "#eb6834", "#1baf7a", "#eda100")  # validated: scripts/validate_palette.js, light
ink <- "#3d3d3a"; muted <- "#8a8984"; grid <- "#e6e5e0"; surface <- "#fcfcfb"

p <- ggplot(agg, aes(cond, collapsed, fill = world)) +
  geom_col(position = position_dodge(width = 0.84), width = 0.8, colour = surface, linewidth = 0.6) +
  scale_fill_manual(values = pal, name = NULL) +
  scale_y_continuous(labels = function(x) paste0(round(100 * x), "%"), expand = expansion(mult = c(0, 0.06))) +
  labs(x = NULL, y = "Seeds collapsed (mean defect > 0.5)",
       title = "No guard collapses least; block guard collapses most",
       subtitle = "Share of seeds collapsed at generation 59, pooled over transparency cost x audit rate (n = 120-180 per bar)") +
  theme_minimal(base_size = 12) +
  theme(plot.background = element_rect(fill = surface, colour = NA),
        panel.grid.major.x = element_blank(), panel.grid.minor = element_blank(),
        panel.grid.major.y = element_line(colour = grid, linewidth = 0.4),
        axis.text = element_text(colour = muted), axis.title.y = element_text(colour = muted, size = 10),
        plot.title = element_text(colour = ink, face = "bold"),
        plot.subtitle = element_text(colour = muted, size = 9.5),
        legend.position = "top", legend.justification = "left", legend.text = element_text(colour = ink),
        plot.margin = margin(14, 16, 10, 12))

ggsave("docs/headline_collapse.png", p, width = 9.5, height = 4.8, dpi = 160, bg = surface)
print(agg)
