import { describe, expect, it } from "vitest";
import {
  currentMonthPeriod,
  firstWorkingDayOfMonth,
  isWorkingDay,
  monthlyReportDue,
  previousMonthPeriod,
  zonedTimeToUtc,
} from "../../src/modules/reports/period.js";

/**
 * The report's period is a local calendar month; every timestamp it counts is UTC.
 *
 * A one-hour error here moves a day of findings into the neighbouring report, and a
 * day-of-week error sends the report on a Sunday to an empty office. Neither shows up in
 * a smoke test, so the cases below are the ones that actually break: month rollover across
 * a year, a zone that observes DST, and months whose first day is a weekend.
 */

const TBILISI = "Asia/Tbilisi"; // UTC+4 all year, no DST.
const LONDON = "Europe/London"; // UTC+0/+1, so it catches offset assumptions.

describe("report period arithmetic", () => {
  it("bounds the previous month by local midnight, not UTC midnight", () => {
    // 5 August 2026, 02:00 UTC -- which is already 06:00 on the 5th in Tbilisi.
    const period = previousMonthPeriod(new Date("2026-08-05T02:00:00Z"), TBILISI);

    // Local midnight on 1 July in UTC+4 is 20:00 on 30 June UTC. Anything scanned in that
    // window belongs to July's report, and a UTC-midnight boundary would file it in June.
    expect(period.start.toISOString()).toBe("2026-06-30T20:00:00.000Z");
    expect(period.end.toISOString()).toBe("2026-07-31T20:00:00.000Z");
    expect(period.label).toBe("2026-07");
  });

  it("rolls back across the year boundary", () => {
    const period = previousMonthPeriod(new Date("2026-01-02T09:00:00Z"), TBILISI);
    expect(period.label).toBe("2025-12");
    expect(period.start.toISOString()).toBe("2025-11-30T20:00:00.000Z");
  });

  it("uses the offset in force in each month, not one offset for both ends", () => {
    // British Summer Time ends on 25 October 2026. A period covering October therefore
    // starts at UTC+1 and ends at UTC+0, and a single-offset implementation is an hour out
    // at one end.
    const period = previousMonthPeriod(new Date("2026-11-03T09:00:00Z"), LONDON);
    expect(period.start.toISOString()).toBe("2026-09-30T23:00:00.000Z");
    expect(period.end.toISOString()).toBe("2026-11-01T00:00:00.000Z");
  });

  it("resolves a local wall-clock time across a spring-forward boundary", () => {
    // Clocks go forward at 01:00 on 29 March 2026 in London.
    expect(zonedTimeToUtc(2026, 3, 29, 0, 30, LONDON).toISOString()).toBe(
      "2026-03-29T00:30:00.000Z",
    );
    expect(zonedTimeToUtc(2026, 3, 29, 3, 30, LONDON).toISOString()).toBe(
      "2026-03-29T02:30:00.000Z",
    );
  });

  it("labels an ad-hoc preview with the month in progress and ends it now", () => {
    const now = new Date("2026-08-17T11:00:00Z");
    const period = currentMonthPeriod(now, TBILISI);
    expect(period.label).toBe("2026-08");
    expect(period.end).toBe(now);
  });
});

describe("scheduling on a working day", () => {
  it("skips a weekend at the start of the month", () => {
    // 1 August 2026 is a Saturday, so the first working day is Monday the 3rd.
    const due = firstWorkingDayOfMonth(new Date("2026-08-01T00:00:00Z"), TBILISI, 9);
    expect(due.toISOString()).toBe("2026-08-03T05:00:00.000Z"); // 09:00 in UTC+4.
    expect(isWorkingDay(due, TBILISI)).toBe(true);
  });

  it("uses the first when the first is itself a weekday", () => {
    // 1 September 2026 is a Tuesday.
    const due = firstWorkingDayOfMonth(new Date("2026-09-10T00:00:00Z"), TBILISI, 9);
    expect(due.toISOString()).toBe("2026-09-01T05:00:00.000Z");
  });

  it("is not due before the configured hour, and stays due afterwards", () => {
    // 08:00 local on the first working day: too early.
    expect(monthlyReportDue(new Date("2026-08-03T04:00:00Z"), TBILISI, 9)).toBe(false);
    expect(monthlyReportDue(new Date("2026-08-03T05:00:00Z"), TBILISI, 9)).toBe(true);
  });

  it("stays due later in the month so an outage delays the report rather than losing it", () => {
    // A container down for the first three days of the month still sends when it returns.
    // Sending twice is prevented by the unique index, not by narrowing this window.
    expect(monthlyReportDue(new Date("2026-08-06T09:00:00Z"), TBILISI, 9)).toBe(true);
  });

  it("is never due on a weekend at the start of the month", () => {
    // Saturday 1 and Sunday 2 August, both after the configured hour.
    expect(monthlyReportDue(new Date("2026-08-01T09:00:00Z"), TBILISI, 9)).toBe(false);
    expect(monthlyReportDue(new Date("2026-08-02T09:00:00Z"), TBILISI, 9)).toBe(false);
  });
});
