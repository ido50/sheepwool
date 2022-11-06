function render(sheepwool, req)
  req["name"] = "SheepWool Example Site"
  req["tags"] = {"one", "two", "three" }
  return "text/html", sheepwool.render_tmpl("/templates/index", req)
end

return {
    ["render"] = render,
}
