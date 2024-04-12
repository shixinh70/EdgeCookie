from PIL import Image
def generate_rainbow_image(colors):
    size = 256
    img = Image.new('RGB', (size, size), color="white")
    pixels = img.load()

    for i, color in enumerate(colors):
        # 計算該數字對應的位置
        x = color % size
        y = color // size

        # 將數字轉換為RGB顏色值
        if 0 <= x < size and 0 <= y < size:
            red = color // 256**2
            green = (color // 256) % 256
            blue = color % 256
            # 將顏色設置到畫布的對應位置
            pixels[x, y] = (red, green, blue)
        else:
            print(f"Index out of range: ({x}, {y})")
    return img

# 從txt文件中讀取數字
with open('murmur2.txt', 'r') as f:
    input_numbers = list(map(int, f.read().split()))

# 生成彩虹圖
rainbow_image = generate_rainbow_image(input_numbers)
# 保存圖片
rainbow_image.save('murmur2_test.png')