import { z } from "zod";

/** Cursor-free offset pagination. Adequate at this scale and far simpler to drive from a table UI. */
export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type PaginationQuery = z.infer<typeof paginationQuerySchema>;

export interface Paginated<T> {
  items: T[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

// Sorting lives in ./sort.js, which owns the direction type along with the per-table
// column declarations that both ends validate and render against.

export const uuidSchema = z.string().uuid();

/** Component ids are bigints in Postgres; they cross the wire as strings to survive JSON. */
export const componentIdSchema = z.string().regex(/^\d+$/, "must be a numeric id");

export const idParamSchema = z.object({ id: uuidSchema });

/** Shape of every error body the API returns. */
export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    /** Field-level validation detail, present on 400s from schema validation. */
    details?: unknown;
  };
}
