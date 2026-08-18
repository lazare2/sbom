/**
 * Calendar arithmetic for the monthly report, in the organisation's timezone.
 *
 * All of this exists because the report's period is a *local* calendar month while every
 * timestamp in the database is UTC. Tbilisi is UTC+4, so a report generated at 09:00 local
 * on 1 September is 05:00 UTC — and a naive `new Date().getUTCMonth()` on a server running
 * in UTC would still agree, right up until the organisation moves to a timezone west of
 * Greenwich or someone runs the job just after midnight. Getting this wrong shifts a whole
 * month of findings into the neighbouring report, which is invisible in testing and obvious
 * to management.
 *
 * Implemented over `Intl` rather than a date library: the conversion needed is small, the
 * IANA rules ship with Node, and a dependency whose only job is timezone maths is a
 * dependency that eventually needs updating for a rule change we would not notice.
 */

/** A report's period: local calendar month, expressed as the UTC instants that bound it. */
export interface ReportPeriod {
  /** Inclusive start. */
  start: Date;
  /** Exclusive end. */
  end: Date;
  /** `YYYY-MM` of the month covered, for labelling and filenames. */
  label: string;
}

interface LocalParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  weekday: number;
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/**
 * Wall-clock fields of an instant in a given zone.
 *
 * `hourCycle: "h23"` rather than `hour12: false`, which is a long-standing quirk: the
 * latter renders midnight as hour 24 in several locales, and a 24 silently becomes the
 * next day when fed back into `Date.UTC`.
 */
function partsIn(instant: Date, timeZone: string): LocalParts {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    weekday: "short",
  });

  const found: Record<string, string> = {};
  for (const part of formatter.formatToParts(instant)) found[part.type] = part.value;

  return {
    year: Number(found.year),
    month: Number(found.month),
    day: Number(found.day),
    hour: Number(found.hour),
    minute: Number(found.minute),
    weekday: Math.max(0, WEEKDAYS.indexOf(found.weekday ?? "")),
  };
}

/**
 * The UTC instant at which a given local wall-clock time occurs in a zone.
 *
 * Converged twice rather than once. The first pass finds the offset in force at the
 * *guessed* instant, which is the wrong side of a DST boundary when the target time is
 * within an hour of the transition; re-measuring at the corrected instant fixes it. A third
 * pass would change nothing for any real zone, since no zone shifts twice in one hour.
 *
 * Ambiguous local times — the hour that repeats when clocks go back — resolve to the first
 * occurrence. That is a one-hour difference once a year on a monthly boundary, and no zone
 * transitions at midnight on the first of a month.
 */
export function zonedTimeToUtc(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  timeZone: string,
): Date {
  const target = Date.UTC(year, month - 1, day, hour, minute, 0, 0);

  let instant = new Date(target);
  for (let pass = 0; pass < 2; pass += 1) {
    const local = partsIn(instant, timeZone);
    const seen = Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, 0, 0);
    const drift = target - seen;
    if (drift === 0) break;
    instant = new Date(instant.getTime() + drift);
  }
  return instant;
}

/** `YYYY-MM` for a local year and month. */
function monthLabel(year: number, month: number): string {
  return `${year}-${String(month).padStart(2, "0")}`;
}

/**
 * The calendar month before the one `now` falls in, as UTC bounds.
 *
 * The report covers a month that has *finished*. A report run on the first working day of
 * September and labelled "September" would cover somewhere between zero and three days, and
 * would be read as a catastrophic improvement.
 */
export function previousMonthPeriod(now: Date, timeZone: string): ReportPeriod {
  const local = partsIn(now, timeZone);
  const year = local.month === 1 ? local.year - 1 : local.year;
  const month = local.month === 1 ? 12 : local.month - 1;

  return {
    start: zonedTimeToUtc(year, month, 1, 0, 0, timeZone),
    end: zonedTimeToUtc(local.year, local.month, 1, 0, 0, timeZone),
    label: monthLabel(year, month),
  };
}

/** The month `now` falls in, used to label an ad-hoc preview honestly as partial. */
export function currentMonthPeriod(now: Date, timeZone: string): ReportPeriod {
  const local = partsIn(now, timeZone);
  return {
    start: zonedTimeToUtc(local.year, local.month, 1, 0, 0, timeZone),
    end: now,
    label: monthLabel(local.year, local.month),
  };
}

/** Monday to Friday, in the given zone. */
export function isWorkingDay(instant: Date, timeZone: string): boolean {
  const weekday = partsIn(instant, timeZone).weekday;
  return weekday >= 1 && weekday <= 5;
}

/**
 * The first Monday-to-Friday day of the local month `instant` falls in, at `hour` local.
 *
 * Public holidays are not modelled. The platform has no holiday calendar, the set differs
 * per country, and a report arriving on a public holiday is read the next morning anyway —
 * whereas a wrong holiday table would suppress the report entirely and silently.
 */
export function firstWorkingDayOfMonth(instant: Date, timeZone: string, hour: number): Date {
  const local = partsIn(instant, timeZone);
  for (let day = 1; day <= 7; day += 1) {
    const candidate = zonedTimeToUtc(local.year, local.month, day, hour, 0, timeZone);
    if (isWorkingDay(candidate, timeZone)) return candidate;
  }
  // Unreachable: any seven consecutive days contain a weekday.
  return zonedTimeToUtc(local.year, local.month, 1, hour, 0, timeZone);
}

/**
 * Whether the scheduled monthly report is due at `now`.
 *
 * Due from the scheduled instant onwards for the rest of the month, rather than only at
 * that exact moment. A container down at 09:00 on the first working day would otherwise
 * skip the month entirely, and a report that arrives three days late is worth far more than
 * one that never arrives. Sending repeatedly is not a risk here: the duplicate guard is the
 * unique index on `(kind, period_start)`, so this predicate decides only *when to try* and
 * the database decides whether it already happened.
 */
export function monthlyReportDue(now: Date, timeZone: string, hour: number): boolean {
  const due = firstWorkingDayOfMonth(now, timeZone, hour);
  if (now.getTime() < due.getTime()) return false;
  const localNow = partsIn(now, timeZone);
  const localDue = partsIn(due, timeZone);
  return localNow.year === localDue.year && localNow.month === localDue.month;
}
