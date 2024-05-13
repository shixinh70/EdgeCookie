from PIL import Image
import colorsys
import sys

def generate_rainbow_image(input_file, output_file):
    size = 256
    img = Image.new('RGB', (size, size), color="black")
    pixels = img.load()
    used_list = [0] * 65536
    
    # 从txt文件中读取数字
    with open(input_file, 'r') as f:
        input_numbers = list(map(int, f.read().split()))

    for i, color in enumerate(input_numbers):
        # 计算该数字对应的位置
        if used_list[color] == 0:
            x = i % size
            y = i // size
            
            # 将x坐标映射到0-1之间
            x_norm = x / (size - 1)
            
            # 将数字映射到HSV色彩空间中的色相值（0-1之间）
            hue = color / 65535.0
            
            # 根据x坐标调整亮度
            # brightness = 0.1 + (1- x_norm) * 0.9  # 0.5表示基础亮度，x_norm*0.5表示最大亮度变化范围
            
            # 将HSV色彩空间中的色相、饱和度、亮度转换为RGB色彩空间中的颜色值
            rgb_color = tuple(int(c * 255) for c in colorsys.hsv_to_rgb(hue, 1.0, 1.0))

            # 将颜色设置到画布的对应位置
            pixels[x, y] = rgb_color
            used_list[color] = 1
    
    # 保存图片
    img.save(output_file)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 ./rainbow.py input_file output_file")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        generate_rainbow_image(input_file, output_file)