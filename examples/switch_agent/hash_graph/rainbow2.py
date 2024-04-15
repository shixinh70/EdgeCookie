import numpy as np
from PIL import Image

# 从文件中读取数据
with open('normal.txt', 'r') as file:
    data = file.read().split()

# 将数据转换为 numpy 数组并重塑为256x256
data = np.array(data, dtype=np.uint16).reshape(256, 256)

# 将16位 RGB565 转换为 RGB888
red = ((data >> 11) & 0x1F) << 3
green = ((data >> 5) & 0x3F) << 2
blue = (data & 0x1F) << 3

# 创建一个 256x256x3 的空白图像
image = np.zeros((256, 256, 3), dtype=np.uint8)

# 将 RGB 值写入图像
image[:,:,0] = red
image[:,:,1] = green
image[:,:,2] = blue

# 保存图像
img = Image.fromarray(image)
img.save('output_image.png')