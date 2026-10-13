/**
 * @name UseDeveloperExceptionPage zonder IsDevelopment check
 * @description UseDeveloperExceptionPage() mag enkel in Development-omgeving.
 *              Zonder IsDevelopment()-check lekt gevoelige foutdetails (stack traces,
 *              environment, etc.) in productie.
 * @kind problem
 * @problem.severity error
 * @id unbreakable/csharp/use-developer-exception-page
 * @tags security
 *       misconfiguration
 *       information-exposure
 * @precision high
 */

import csharp

// Zoek aanroepen van UseDeveloperExceptionPage() die NIET binnen een
// IfStmt met IsDevelopment() check vallen.
// build-mode: none werkt omdat we enkel methodenaam matchen.
from MethodCall mc
where
  mc.getTarget().getName() = "UseDeveloperExceptionPage"
  and not exists(IfStmt guard |
    guard.getCondition() instanceof MethodCall and
    guard.getCondition().(MethodCall).getTarget().getName() = "IsDevelopment"
    and guard.getThen() = mc.getEnclosingStmt().getParent()
  )
select mc,
  "UseDeveloperExceptionPage() staat aan zonder IsDevelopment() check. " +
    "Gevoelige foutdetails (stack traces, environment) lekken in productie. " +
    "Plaats binnen: if (app.Environment.IsDevelopment()) { ... }"