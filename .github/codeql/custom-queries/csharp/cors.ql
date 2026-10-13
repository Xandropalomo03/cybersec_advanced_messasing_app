/**
 * @name CORS staat open voor alle origins
 * @description CORS-policy gebruikt AllowAnyOrigin(): elke website mag API calls
 *              doen namens de ingelogde gebruiker. Het echte risico is dat de
 *              X-User header meegestuurd mag worden (AllowAnyOrigin blokkeert
 *              cookies, maar niet custom headers). Beperk tot specifieke domeinen.
 * @kind problem
 * @problem.severity error
 * @id unbreakable/csharp/allow-any-origin
 * @tags security
 *       cors
 * @precision high
 */

import csharp

from MethodCall mc
where mc.getTarget().getName() = "AllowAnyOrigin"
select mc,
  "CORS policy staat toe aan alle origins (AllowAnyOrigin). " +
    "Elke website mag de X-User header meesturen en zich voordoen als een gebruiker. " +
    "Beperk tot specifieke domeinen."