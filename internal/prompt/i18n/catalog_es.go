package i18n

// es is the Spanish catalogue: neutral Spanish, addressing the user as "tú".
// The product name, scope tokens (once, session, project), layer names,
// secret names and host names are never translated.
var es = map[string]string{}

func init() {
	add(es, map[string]string{
		"btn.save":     "Guardar",
		"btn.cancel":   "Cancelar",
		"btn.continue": "Continuar",
		"btn.confirm":  "Confirmar",
		"btn.decline":  "Rechazar",
		"btn.done":     "Hecho",
		"btn.ok":       "Aceptar",

		"heading.request":    "Solicitud de secreto",
		"heading.permission": "Solicitud de permiso",
		"heading.confirm":    "Confirmar",

		"row.who":           "Quién",
		"row.secret":        "Secreto",
		"row.why":           "Motivo",
		"row.saved_in":      "Se guarda en",
		"row.about":         "Descripción",
		"row.already_saved": "Ya guardados",
		"row.field":         "Campo",
		"row.value":         "Valor",
		"val.all_projects":  "todos los proyectos",
		"val.project":       "proyecto %[1]s",
		"val.not_asked":     "%[1]s (no se vuelven a pedir)",
		"val.field_of":      "%[1]d de %[2]d (%[3]s)",
		"val.new":           "nuevo",
		"val.replaces":      "reemplaza el valor guardado",

		"input.hidden":  "Pega o escribe el valor. El agente nunca lo ve:",
		"input.visible": "Escribe el valor (se muestra mientras escribes):",
		"input.form":    "Completa cada campo. El agente nunca ve lo que escribes:",
		"field.hidden":  " (oculto)",
		"field.shown":   " (se muestra mientras escribes)",

		"who.agent":      "un agente",
		"who.your_agent": "tu agente",
		"who.cli":        "tú (qbit-vault)",
		"who.session":    "%[1]s (sesión %[2]s)",

		"eye.show":       "Mostrar",
		"eye.hide":       "Ocultar",
		"eye.show_value": "Mostrar valor",
		"eye.hide_value": "Ocultar valor",
		"eye.width":      "76",

		"pass.again":          "Escribe la frase de contraseña de nuevo",
		"pass.mismatch":       "Las frases de contraseña no coinciden.",
		"pass.mismatch_retry": "Las frases de contraseña no coinciden. Inténtalo de nuevo.",
		"pass.vault.heading":  "Frase de contraseña de la bóveda",
		"pass.vault.label":    "Frase de contraseña de la bóveda",
		"pass.vault.again":    "Escribe la frase de contraseña de nuevo",
		"pass.export.heading": "Frase de contraseña de exportación",
		"pass.export.label":   "Frase de contraseña de exportación (protege este archivo de copia de seguridad)",
		"pass.export.again":   "Escribe de nuevo la frase de contraseña de exportación",
		"pass.import.heading": "Frase de contraseña de exportación",
		"pass.import.label":   "Frase de contraseña del archivo de exportación",

		"tty.request_title": "QBit Vault: solicitud de secreto",
		"tty.value":         "Valor",
		"tty.answer":        "Respuesta",
		"tty.hidden":        "%[1]s (oculto): ",
		"tty.shown":         "%[1]s (se muestra mientras escribes): ",
		"tty.choice":        "Opción [%[1]d]: ",
		"tty.choice_retry":  "Escribe un número del 1 al %[1]d, o pulsa Intro para elegir la opción predeterminada.",
		"tty.yes_no":        " [s/N] ",
		"tty.yes_words":     "s,si,sí,y,yes",
		"tty.press_enter":   "Pulsa Intro al terminar. ",

		"mark.perm_prefix": "no ",
		"mark.perm_a":      "permitir",
		"mark.perm_b":      "preguntarme antes",
		"mark.removal_a":   "eliminar",
		"mark.removal_b":   "borrar",
	})
}
