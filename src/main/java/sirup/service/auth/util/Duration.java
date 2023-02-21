package sirup.service.auth.util;

public record Duration(int duration, DurationUnit durationUnit) {
    final static Duration SHORT = new Duration(12, DurationUnit.HOUR);
    final static Duration MEDIUM = new Duration(3, DurationUnit.DAY);
    final static Duration LONG = new Duration(1, DurationUnit.WEEK);
    final static Duration VERY_LONG = new Duration(1, DurationUnit.MONTH);

    final static long MILLISECOND_TO_HOUR = 3600000;
    public enum DurationUnit {
        HOUR(MILLISECOND_TO_HOUR),
        DAY(24 * MILLISECOND_TO_HOUR),
        WEEK(7 * 24 * MILLISECOND_TO_HOUR),
        MONTH(30 * 24 * MILLISECOND_TO_HOUR);
        final long unit;
        DurationUnit(final long unit) {
            this.unit = unit;
        }
    }
}
