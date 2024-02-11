import xml.dom.minidom

def update_threshold(xml_file, file_mask, threshold_percent, threshold_files):
    doc                 = xml.dom.minidom.parse(xml_file)
    file_mask_data_list = doc.getElementsByTagName("FileMaskData")
    found               = False
  
    for file_mask_data in file_mask_data_list:
        current_file_mask = file_mask_data.getElementsByTagName("FileMask")[0].firstChild.nodeValue
        if current_file_mask == file_mask:
            file_mask_data.getElementsByTagName("ThresholdPercent")[0].firstChild.nodeValue = str(threshold_percent)
            file_mask_data.getElementsByTagName("ThresholdFiles")[0].firstChild.nodeValue = str(threshold_files)
            found = True
            break

    # Warning message if the file mask was not found
    if not found:
        print(f"Warning: File mask '{file_mask}' not found in the XML file.")
        return

    # Write the updated XML back
    with open(xml_file, "w") as f:
        doc.writexml(f)

    print("XML file updated successfully.")

if __name__ == "__main__":
    # Default path to the TrackedFiles.xml
    xml_file_path       = r'C:\Program Files\Veeam\Backup and Replication\Backup\TrackedFiles.xml'
    file_mask           = input("Enter the file mask to update: ")
    update_needed       = False
    file_mask_data_list = xml.dom.minidom.parse(xml_file_path).getElementsByTagName("FileMaskData")
  
    for file_mask_data in file_mask_data_list:
        current_file_mask = file_mask_data.getElementsByTagName("FileMask")[0].firstChild.nodeValue
        if current_file_mask == file_mask:
            update_needed = True
            break

    if not update_needed:
        print(f"Warning: File mask '{file_mask}' not found in the XML file.")
        exit()

    threshold_percent = int(input("Enter the new threshold percent: "))
    threshold_files   = int(input("Enter the new threshold files: "))

    # Update the XML file
    update_threshold(xml_file_path, file_mask, threshold_percent, threshold_files)
