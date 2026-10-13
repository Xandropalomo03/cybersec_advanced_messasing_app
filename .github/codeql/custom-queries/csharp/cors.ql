/**
 * @name CORS staat open voor alle origins
 * @description CORS-policy gebruikt AllowAnyOrigin(): elke website mag API-aanroepen
 *              doen namens de ingelogde gebruiker (cookie-based requests meegestuurd).
 *              Beperk tot de specifieke domeinen van de applicatie.
 * @kind problem
 * @problem.severity error
 * @id unbreakable/csharp/allow-any-origin
 * @tags security
 *       cors
 * @precision high
 */

import csharp

// Naam-gebaseerd: werkt ook met build-mode: none (geen volledige type-resolutie).
from MethodCall mc
where mc.getMethod().getName() = "AllowAnyOrigin"
select mc,
  "CORS policy staat toe aan alle origins (AllowAnyOrigin). " +
    "Beperk tot specifieke domeinen om cross-origin misbruik te voorkomen."