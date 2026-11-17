import { AppError } from "../../lib/errors.js";

/** A switched-off module's address: 409, so a page says "not enabled" rather than "empty". */
export class ModuleDisabledError extends AppError {
  constructor(name: string) {
    super({
      statusCode: 409,
      code: "module_disabled",
      message: `${name} is switched off. An administrator can switch it on under Administration -> Modules; its data was kept.`,
    });
  }
}
