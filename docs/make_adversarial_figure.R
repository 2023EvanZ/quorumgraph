# Adversarial-drift figure for the README: collapse and capture by lineage-guard mode,
# random vs adversarial successor drift, audits on (0.05 and 0.25, both costs pooled).
# Reads runs/ (gitignored; regenerate with runs/overnight2.sh and runs/overnight3.sh)
# and writes docs/adversarial_capture.png.
#   Rscript docs/make_adversarial_figure.R
suppressPackageStartupMessages(library(ggplot2))

files <- c("runs/selection-drift02/generations.csv",
           "runs/selection-drift04/generations.csv",
           "runs/selection-adversarial/generations.csv")
d <- do.call(rbind, lapply(files, function(f) {
  x <- read.csv(f, stringsAsFactors = FALSE)
  x <- x[x$audit_prob > 0 & x$audit_channel == "sim", ]
  if (!"drift_mode" %in% names(x)) x$drift_mode <- "random"
  x$drift_mode[is.na(x$drift_mode) | x$drift_mode == ""] <- "random"
  # each run's last generation: one run went extinct at generation 16 after capture
  x <- x[order(-x$generation), ]
  key <- paste(x$world, x$seed, x$transparency_cost, x$audit_prob, x$drift_prob, x$drift_mode)
  x[!duplicated(key), ]
}))
keep <- setNames(c("gated (no promotion)", "no guard", "soft guard", "block guard"),
                 c("gated", "recursive", "recursive_soft", "recursive_guarded"))
d <- d[d$world %in% names(keep), ]
d$world <- factor(keep[d$world], levels = keep)
d$cond <- factor(sprintf("%s drift %s", ifelse(d$drift_mode == "adversarial", "Adversarial", "Random"), d$drift_prob),
                 levels = c("Random drift 0.2", "Random drift 0.4", "Adversarial drift 0.2", "Adversarial drift 0.4"))
d$collapsed <- d$mean_defect > 0.5
d$td <- suppressWarnings(as.numeric(d$trusted_defect))

coll <- aggregate(collapsed ~ world + cond, d, function(v) c(k = sum(v), n = length(v)))
coll <- data.frame(coll[1:2], k = coll$collapsed[, "k"], n = coll$collapsed[, "n"],
                   panel = "Seeds collapsed (population mean defect > 0.5)")
dt <- d[!is.na(d$td), ]
cap <- aggregate(td ~ world + cond, dt, function(v) c(k = sum(v > 0.5), n = length(v)))
cap <- data.frame(cap[1:2], k = cap$td[, "k"], n = cap$td[, "n"],
                  panel = "Trusted set captured (trusted mean defect > 0.5)")
agg <- rbind(coll, cap)
agg$share <- agg$k / agg$n
agg$panel <- factor(agg$panel, levels = unique(agg$panel))

pal <- c("#2a78d6", "#eb6834", "#1baf7a", "#eda100")  # validated: same palette as headline figure
ink <- "#3d3d3a"; muted <- "#8a8984"; grid <- "#e6e5e0"; surface <- "#fcfcfb"

p <- ggplot(agg, aes(cond, share, fill = world)) +
  geom_col(position = position_dodge(width = 0.84), width = 0.8, colour = surface, linewidth = 0.6) +
  # count labels on the capture panel only, so the zero bars are visible as zeros
  geom_text(data = agg[agg$panel == levels(agg$panel)[2], ], aes(label = k, group = world),
            position = position_dodge(width = 0.84), vjust = -0.5, size = 3, colour = muted) +
  facet_wrap(~panel, ncol = 1, scales = "free_y") +
  scale_fill_manual(values = pal, name = NULL) +
  scale_y_continuous(labels = function(x) paste0(round(100 * x), "%"), expand = expansion(mult = c(0, 0.08))) +
  labs(x = NULL, y = NULL,
       title = "Against drift that hides itself, only the unguarded world gets captured",
       subtitle = paste("Final generation, audits on (0.05 and 0.25), costs pooled; n = 120 seeds per bar for collapse.",
                        "Capture is out of runs that still had trusted agents.", sep = "\n")) +
  theme_minimal(base_size = 12) +
  theme(plot.background = element_rect(fill = surface, colour = NA),
        panel.grid.major.x = element_blank(), panel.grid.minor = element_blank(),
        panel.grid.major.y = element_line(colour = grid, linewidth = 0.4),
        axis.text = element_text(colour = muted),
        strip.text = element_text(colour = ink, hjust = 0, size = 10.5),
        plot.title = element_text(colour = ink, face = "bold"),
        plot.subtitle = element_text(colour = muted, size = 9.5),
        legend.position = "top", legend.justification = "left", legend.text = element_text(colour = ink),
        plot.margin = margin(14, 16, 10, 12))

ggsave("docs/adversarial_capture.png", p, width = 9.5, height = 6.4, dpi = 160, bg = surface)
print(agg[order(agg$panel, agg$cond, agg$world), c("panel", "cond", "world", "k", "n")], row.names = FALSE)
