export async function resolve(specifier, context, next) {
  const ctx = { ...context, conditions: ["@afr/source", ...context.conditions] };
  try {
    return await next(specifier, ctx);
  } catch (err) {
    if (
      err?.code === "ERR_MODULE_NOT_FOUND" &&
      specifier.endsWith(".js") &&
      !specifier.includes("node_modules")
    ) {
      return next(`${specifier.slice(0, -3)}.ts`, ctx);
    }
    throw err;
  }
}
