function render(sheepwool, db, req)
  req["name"] = "SheepWool Example Site"
  req["tags"] = {"one", "two", "three" }
  return "text/html", sheepwool.render_tmpl(db, "/templates/index", req)
end

return {
    ["render"] = render,
}
