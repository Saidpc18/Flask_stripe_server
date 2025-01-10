from PIL import Image, ImageDraw, ImageFont

# Crear un lienzo en blanco
width, height = 800, 800
image = Image.new("RGBA", (width, height), (255, 255, 255, 0))
draw = ImageDraw.Draw(image)

# Colores
background_color = (255, 255, 255, 255)  # Blanco
circle_color = (60, 60, 60)  # Gris oscuro
icon_fill_color = (255, 255, 255, 255)  # Blanco
icon_accent_color = (60, 60, 60)  # Gris oscuro
text_color = (40, 40, 40)  # Gris

# Fondo
draw.rectangle([0, 0, width, height], fill=background_color)

# Dibujar el círculo
circle_center = (400, 300)
circle_radius = 200
draw.ellipse(
    [
        (circle_center[0] - circle_radius, circle_center[1] - circle_radius),
        (circle_center[0] + circle_radius, circle_center[1] + circle_radius),
    ],
    fill=circle_color,
)

# Dibujar la forma del "binder" (icono principal)
binder_x, binder_y = 300, 200
binder_width, binder_height = 200, 250

# Fondo del icono (parte interna blanca)
draw.rectangle(
    [(binder_x, binder_y), (binder_x + binder_width, binder_y + binder_height)],
    fill=icon_fill_color,
)

# Parte "trasera" del binder (segunda hoja)
back_offset = 15
draw.rectangle(
    [
        (binder_x - back_offset, binder_y + back_offset),
        (binder_x + binder_width - back_offset, binder_y + binder_height + back_offset),
    ],
    fill=icon_fill_color,
)

# Contorno del icono
draw.rectangle(
    [(binder_x, binder_y), (binder_x + binder_width, binder_y + binder_height)],
    outline=icon_accent_color,
    width=8,
)

# Dibujar círculos pequeños (los puntos del binder)
dot_radius = 10
dot_positions = [
    (binder_x + 50, binder_y + 75),
    (binder_x + 50, binder_y + 150),
]
for dot_x, dot_y in dot_positions:
    draw.ellipse(
        [
            (dot_x - dot_radius, dot_y - dot_radius),
            (dot_x + dot_radius, dot_y + dot_radius),
        ],
        fill=icon_accent_color,
    )

# Agregar el texto "BINDER"
font_size = 60
try:
    font_path = "arial.ttf"  # Cambia según tu sistema
    font = ImageFont.truetype(font_path, font_size)
except Exception:
    font = ImageFont.load_default()

text = "BINDER"
text_width, text_height = draw.textsize(text, font=font)
text_x = (width - text_width) // 2
text_y = 600

draw.text((text_x, text_y), text, fill=text_color, font=font)

# Guardar el logo
output_path = "binder_logo_python.png"
image.save(output_path)
print(f"Logo guardado en {output_path}")
