// Heavily based on https://github.com/Pryz/terraform-provider-ldap, see LICENSE

package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/text/encoding/unicode"
)

func resourceLDAPObject() *schema.Resource {
	return &schema.Resource{
		Create: resourceLDAPObjectCreate,
		Read:   resourceLDAPObjectRead,
		Update: resourceLDAPObjectUpdate,
		Delete: resourceLDAPObjectDelete,
		Exists: resourceLDAPObjectExists,

		// Importer: &schema.ResourceImporter{
		// 	State: resourceLDAPObjectImport,
		// },

		Schema: map[string]*schema.Schema{
			"dn": {
				Type:        schema.TypeString,
				Description: "The Distinguished Name (DN) of the object, as the concatenation of its RDN (unique among siblings) and its parent's DN.",
				Required:    true,
				ForceNew:    true,
			},
			"object_classes": {
				Type:        schema.TypeSet,
				Description: "The set of classes this object conforms to (e.g. organizationalUnit, inetOrgPerson).",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				Required:    true,
			},
			"attributes": {
				Type:        schema.TypeMap,
				Description: "The map of attributes of this object; each attribute can be multi-valued.",

				Elem: &schema.Schema{
					Type:        schema.TypeString,
					Description: "The value for a given attribute. If it is a valid json array then it will be decoded into that.",
				},
				Optional: true,
			},
			"skip_attributes": {
				Type:        schema.TypeSet,
				Description: "List of attributes which should be ignored",
				Set:         schema.HashString,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
			},
		},
	}
}

func resourceLDAPObjectExists(d *schema.ResourceData, meta interface{}) (b bool, e error) {
	l := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::exists - checking if %q exists", dn)

	// search by primary key (that is, set the DN as base DN and use a "base
	// object" scope); no attributes are retrieved since we are onòy checking
	// for existence; all objects have an "objectClass" attribute, so the filter
	// is a "match all"
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	)

	_, err := l.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 { // no such object
				log.Printf("[WARN] ldap_object::exists - lookup for %q returned no value: deleted on server?", dn)
				return false, nil
			}
		}
		log.Printf("[DEBUG] ldap_object::exists - lookup for %q returned an error %v", dn, err)
		return false, err
	}

	log.Printf("[DEBUG] ldap_object::exists - object %q exists", dn)
	return true, nil
}

func maybeJSONStringToArray(in string) []string {
	log.Printf("[TRACE] ldap_object::update decoding %s", in)
	if strings.HasPrefix(strings.TrimSpace(in), "[") {
		ret := []string{}
		err := json.Unmarshal([]byte(in), &ret)
		if err != nil {
			log.Printf("[DEBUG] ldap_object::jsonDecode Could not deocde expected array")
		} else {
			return ret
		}
	}
	return []string{in}
}

func resourceLDAPObjectCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::create - creating a new object under %q", dn)

	request := ldap.NewAddRequest(dn, []ldap.Control{})

	// retrieve classe from HCL
	objectClasses := []string{}
	for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
		log.Printf("[DEBUG] ldap_object::create - object %q has class: %q", dn, oc.(string))
		objectClasses = append(objectClasses, oc.(string))
	}
	request.Attribute("objectClass", objectClasses)

	attributesToSkip := []string{"objectClass"}
	for _, attrName := range (d.Get("skip_attributes").(*schema.Set)).List() {
		attributesToSkip = append(attributesToSkip, attrName.(string))
	}
	log.Printf("[DEBUG] ldap_object::create - object %q going to skip attributes: %v", dn, attributesToSkip)

	// if there is a non empty list of attributes, loop though it and
	// create a new map collecting attribute names and its value(s); we need to
	// do this because we could not model the attributes as a map[string][]string
	// due to an appareent limitation in HCL; we have a []map[string]string, so
	// we loop through the list and accumulate values when they share the same
	// key, then we use these as attributes in the LDAP client.
	if v, ok := d.GetOk("attributes"); ok {
		attributes := v.(map[string]interface{})

		for name, value := range attributes {
			if stringListContains(name, attributesToSkip) {
				continue
			}
			valsToSet := maybeJSONStringToArray(value.(string))
			log.Printf("[DEBUG] ldap_object::create - %q has attribute %s => %v", dn, name, valsToSet)
			request.Attribute(name, valsToSet)
		}
	}

	log.Printf("[TRACE] ldap_object::create - %q going to send request: %+v", dn, request)
	err := client.Add(request)
	if err != nil {
		log.Printf("[DEBUG] ldap_object::creaate - %q got error in sending request", dn)
		return err
	}

	log.Printf("[DEBUG] ldap_object::create - object %q added to LDAP server", dn)

	d.SetId(dn)
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectRead(d *schema.ResourceData, meta interface{}) error {
	return readLDAPObject(d, meta, true)
}

func resourceLDAPObjectUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)

	log.Printf("[DEBUG] ldap_object::update - performing update on %q", d.Id())

	modify := ldap.NewModifyRequest(d.Id(), []ldap.Control{})

	// handle objectClasses
	if d.HasChange("object_classes") {
		classes := []string{}
		for _, oc := range (d.Get("object_classes").(*schema.Set)).List() {
			classes = append(classes, oc.(string))
		}
		log.Printf("[DEBUG] ldap_object::update - updating classes of %q, new value: %v", d.Id(), classes)
		modify.Replace("objectClass", classes)
	}

	if d.HasChange("attributes") {
		o, n := d.GetChange("attributes")
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("old attributes map", o))
		log.Printf("[DEBUG] ldap_object::update - \n%s", printAttributes("new attributes map", n))

		err := computeAndAddDeltas(modify, o.(map[string]interface{}), n.(map[string]interface{}))
		if err != nil {
			return err
		}
	}

	err := client.Modify(modify)
	if err != nil {
		log.Printf("[ERROR] ldap_object::update - error modifying LDAP object %q with values %v", d.Id(), err)
		return err
	}
	return resourceLDAPObjectRead(d, meta)
}

func resourceLDAPObjectDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::delete - removing %q", dn)

	request := ldap.NewDelRequest(dn, nil)

	err := client.Del(request)
	if err != nil {
		log.Printf("[ERROR] ldap_object::delete - error removing %q: %v", dn, err)
		return err
	}
	log.Printf("[DEBUG] ldap_object::delete - %q removed", dn)
	return nil
}

func stringListContains(needle string, haystack []string) bool {
	for _, h := range haystack {
		if needle == h {
			return true
		}
	}
	return false
}

func readLDAPObject(d *schema.ResourceData, meta interface{}, updateState bool) error {
	client := meta.(*ldap.Conn)
	dn := d.Get("dn").(string)

	log.Printf("[DEBUG] ldap_object::read - looking for object %q", dn)

	// when searching by DN, you don't need t specify the base DN a search
	// filter a "subtree" scope: just put the DN (i.e. the primary key) as the
	// base DN with a "base object" scope, and the returned object will be the
	// entry, if it exists
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectclass=*)",
		[]string{"*"},
		nil,
	)

	searchResult, err := client.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 && updateState { // no such object
				log.Printf("[WARN] ldap_object::read - object not found, removing %q from state because it no longer exists in LDAP", dn)
				d.SetId("")
				return nil
			}
		}
		log.Printf("[DEBUG] ldap_object::read - lookup for %q returned an error %v", dn, err)
		return err
	}

	log.Printf("[DEBUG] ldap_object::read - query for %q returned %v", dn, searchResult)

	d.SetId(dn)
	d.Set("object_classes", searchResult.Entries[0].GetAttributeValues("objectClass"))

	attributesToSkip := []string{"objectClass"}
	for _, attrName := range (d.Get("skip_attributes").(*schema.Set)).List() {
		attributesToSkip = append(attributesToSkip, attrName.(string))
	}
	log.Printf("[DEBUG] ldap_object::create - object %q going to skip attributes: %v", dn, attributesToSkip)

	// now deal with attributes
	attributes := make(map[string]string)

	for _, attribute := range searchResult.Entries[0].Attributes {
		log.Printf("[DEBUG] ldap_object::read - treating attribute %q of %q (%d values: %v)", attribute.Name, dn, len(attribute.Values), attribute.Values)
		if stringListContains(attribute.Name, attributesToSkip) {
			// skip: we don't treat object classes as ordinary attributes
			log.Printf("[DEBUG] ldap_object::read - skipping attribute %q of %q", attribute.Name, dn)
			continue
		}
		if len(attribute.Values) == 1 {
			// we don't treat the RDN as an ordinary attribute
			a := fmt.Sprintf("%s=%s", attribute.Name, attribute.Values[0])
			if strings.HasPrefix(dn, a) {
				log.Printf("[DEBUG] ldap_object::read - skipping RDN %q of %q", a, dn)
				continue
			}
		}
		if len(attribute.Values) == 1 {
			log.Printf("[DEBUG] ldap_object::read - adding single attribute %q to %q", attribute.Name, dn)
			attributes[attribute.Name] = attribute.Values[0]
		} else {
			log.Printf("[DEBUG] ldap_object::read - adding array attribute %q to %q (%d values)", attribute.Name, dn, len(attribute.Values))
			val, err := json.Marshal(attribute.Values)
			if err != nil {
				log.Printf("[ERROR] ldap_object::read - error marshalling an erro of values into a string")
				return err
			}
			attributes[attribute.Name] = string(val)
		}
	}

	log.Printf("[TRACE] ldap_object::read setting ldap attributes for %q to %+v", dn, attributes)
	if err := d.Set("attributes", attributes); err != nil {
		log.Printf("[WARN] ldap_object::read - error setting LDAP attributes for %q : %v", dn, err)
		return err
	}
	return nil
}

// computes the hash of the map representing an attribute in the attributes set
func attributeHash(v interface{}) int {
	values := v.([]interface{})
	var buffer bytes.Buffer
	buffer.WriteString("[]string {")
	for _, v := range values {
		buffer.WriteString(fmt.Sprintf("%v,\n", v))
	}
	buffer.WriteRune('}')
	h := int(crc32.ChecksumIEEE([]byte(buffer.String())))
	if h >= 0 {
		return h
	}
	if -h >= 0 {
		return -h
	}
	return 0
}

func printAttributes(prefix string, attributes interface{}) string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%s: {\n", prefix))
	if attributes, ok := attributes.(map[string][]interface{}); ok {
		for name, attributeValues := range attributes {
			for _, v := range attributeValues {
				buffer.WriteString(fmt.Sprintf("    %q: %s\n", name, v))
			}
		}
		buffer.WriteRune('}')
	}
	return buffer.String()
}

func computeAndAddDeltas(modify *ldap.ModifyRequest, oldAttrs, newAttrs map[string]interface{}) error {
	// If the new attrs doesn't have a key that the old attrs did then we delete that key
	for oldName, _ := range oldAttrs {
		if _, ok := newAttrs[oldName]; !ok {
			log.Printf("[TRACE] ldap_object::read Going to remove attribute %s", oldName)
			modify.Delete(oldName, []string{})
		}
	}

	// If the new attrs has a key that oldAttrs didn't, then we add that key
	for newName, v := range newAttrs {
		if _, ok := oldAttrs[newName]; !ok {
			log.Printf("[TRACE] ldap_object::read Going to add attribute %s", newName)
			modify.Add(newName, maybeJSONStringToArray(v.(string)))
		}
	}

	// If they both contain the attribute, and they attribute is different, then replace
	for name, newValue := range newAttrs {
		if oldValue, ok := oldAttrs[name]; ok {
			if oldValue != newValue {
				log.Printf("[TRACE] ldap_object::read Going to replace attribute %s", name)
				modify.Replace(name, maybeJSONStringToArray(newValue.(string)))
			}
		}
	}

	return nil
}

func toAttributeValue(name, value string) string {
	if name == "unicodePwd" {
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
		pwdEncoded, _ := utf16.NewEncoder().String("\"" + value + "\"")
		return pwdEncoded
	}
	return value
}
